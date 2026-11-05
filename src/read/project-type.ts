// Plan J sub-task J2 (DECISIONS #121): what each service is (static site, library, CLI, server, container), with its evidence, read by code and
// never by the AI. Two phases (ruling B2):
//   - projectTypeOf, in readService next to notStandaloneOf: the local facts (the static decision, library by its manifest, cli, container);
//   - finishProjectTypes, after readWorkflows: `library` for a published package, `server` by baseRunnable on the finished service (ruling S1:
//     publishedPackage, known only after the workflow pass, changes it) or for an unsure static site (controller ruling, fix round 1; not for a
//     folder that isn't standalone or has library evidence, fix round 2), and for a static site one evidence line per workflow that deploys to
//     a static host. A static host never changes a type.
//
// Only a static site changes the checks (isRunnable drops image build and scan, DAST, API DAST and the created Dockerfile), so the static
// decision is the one that must never be wrong toward static (#121: when unsure, the stricter type wins). It is stated as properties, for any
// repo: a static generator is a dependency AND its config, when it decides, is read as code and says static AND nothing in the service can run
// as a server. Any doubt gives `unsure: true` and not static. Rules (ruling S13):
//   generator   one of next (only with `output: 'export'`, read from the parsed next.config), astro (static unless its config sets a server
//               output or an adapter, or an adapter package is a dependency), @docusaurus/core, gatsby, @11ty/eleventy, vitepress, vite (a
//               `build` script running `vite build`); the package must be in dependencies or devDependencies. The first one present decides.
//   config      parsed (sucrase strips TypeScript, acorn parses; as test-rules.ts does), never matched as text, so a comment or a string
//               elsewhere counts for nothing. Next.js: the default export (directly, through one const, or module.exports) must be an object
//               literal with exactly one non-computed `output` property whose value is the literal 'export', no spread, no wrapper call, and
//               nothing else may write to it. Two configs of one generator, or one pipegen can't read, → unsure.
//   server      a port default in the code; a server package (SERVER_DEPS, or a meta-framework that renders on a server) other than the
//               generator; a server route or function folder (pages/api, app/**/route.*, src/ forms of both, middleware, api/, functions/,
//               netlify/functions); code that starts a server (createServer, .listen(, Bun.serve, Deno.serve); a start, dev or serve script that
//               isn't the generator's own command; Astro: a server output, an adapter key, setAdapter or an adapter package; Gatsby: src/api,
//               getServerData, an adapter. Read over the service's own files minus those git ignores and that git's index doesn't list (J1's
//               rule: a build folder can't flip the type; a committed one counts). More server signs is always the safe direction.
// Evidence lines hold fixed wording and repo-relative paths that pass PLAIN_PATH_RE only (ruling S14), never repo text.
import { parse } from 'acorn';
import { transform } from 'sucrase';
import type { ExistingWorkflow, Language, ProjectType, RepoProfile, Service, ServiceType, StaticHost } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { readGitIndexPaths } from './git-index.js';
import { loadIgnore } from './gitignore.js';
import { regexLines, regexSafe } from './limits.js';
import { CODE_FILE_RE, PLAIN_PATH_RE, PORT_RULES, asObj, asString, baseOf, inDir, isTestFile, type Obj } from './manifest.js';
import { RUN_SCRIPTS, SERVER_DEPS, baseRunnable, type KindInput } from './service-kind.js';

/** The order of ProjectType.types. */
export const SERVICE_TYPES: readonly ServiceType[] = Object.freeze(['static-site', 'library', 'cli', 'server', 'container']);

/** What projectTypeOf reads: the service-kind input, the service's package.json (`{}` when none), and git's view of untracked ignored files. */
export interface TypeInput extends KindInput {
  manifest: Obj;
  /**
   * Loads "is this path git-ignored and not in git's index?" (J1's rule), once per repo; called only when a static generator is found.
   * Absent = no path is left out.
   */
  untrackedIgnored?: () => Promise<(rel: string) => boolean>;
  /** Fix round 1 (review J2 I2): other languages the folder holds (Service.alsoLanguages): a server sign for a static decision. */
  alsoLanguages?: readonly Language[];
  /** Fix round 1 (review J2 I1): the repo's file listing was cut (the read limit) or dropped paths, so some files were never looked at. */
  listingIncomplete?: boolean;
}

/** One `--type` choice (J5): `service: null` = the repo's only service. */
export interface TypeOverride { service: string | null; type: ServiceType }

// ---------- bounds ----------

/** Code files read for server signs, and their bytes together; past either the service is unsure (pipegen couldn't look at all of it). */
const MAX_SIGNAL_FILES = 2000;
const MAX_SIGNAL_BYTES = 32 * 1024 * 1024;
/** A config file bigger than this isn't parsed (unsure). */
const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_DEPTH = 300;

// ---------- the generators ----------

type Gen = 'next' | 'astro' | 'docusaurus' | 'gatsby' | 'eleventy' | 'vitepress' | 'vite';
const GENERATORS: readonly { gen: Gen; pkg: string; label: string }[] = [
  { gen: 'next', pkg: 'next', label: 'Next.js' },
  { gen: 'astro', pkg: 'astro', label: 'Astro' },
  { gen: 'docusaurus', pkg: '@docusaurus/core', label: 'Docusaurus' },
  { gen: 'gatsby', pkg: 'gatsby', label: 'Gatsby' },
  { gen: 'eleventy', pkg: '@11ty/eleventy', label: 'Eleventy' },
  { gen: 'vitepress', pkg: 'vitepress', label: 'VitePress' },
  { gen: 'vite', pkg: 'vite', label: 'Vite' },
];
const CONFIG_EXTS = ['js', 'mjs', 'cjs', 'ts', 'mts', 'cts'];
/** A command's arguments after the generator's own sub-command: plain words only (no shell operators, quotes or substitutions). */
const ARGS = String.raw`(?:\s+[A-Za-z0-9=:./_@-]+)*\s*$`;
const RUNNER = String.raw`^\s*(?:(?:npx|bunx|pnpm\s+exec|yarn)\s+)?`;
/** Each generator's own run commands (start, dev and serve scripts that run one of these are no server sign). */
const OWN_COMMAND: Readonly<Record<Gen, RegExp>> = {
  next: new RegExp(`${RUNNER}next\\s+(?:dev|build|start)${ARGS}`),
  astro: new RegExp(`${RUNNER}astro\\s+(?:dev|preview)${ARGS}`),
  docusaurus: new RegExp(`${RUNNER}docusaurus\\s+(?:start|serve)${ARGS}`),
  gatsby: new RegExp(`${RUNNER}gatsby\\s+(?:develop|serve)${ARGS}`),
  eleventy: new RegExp(`${RUNNER}eleventy\\s+--serve${ARGS}`),
  vitepress: new RegExp(`${RUNNER}vitepress\\s+(?:dev|preview)${ARGS}`),
  vite: new RegExp(`${RUNNER}vite(?:\\s+(?:dev|serve|preview))?${ARGS}`),
};
/** A `vite build` command inside a build script (one of its `&&` parts). */
const VITE_BUILD = new RegExp(`${RUNNER}vite\\s+build${ARGS}`);
/** Meta-frameworks that render pages on a server, on top of SERVER_DEPS (a dependency is a server sign). */
const SSR_DEPS: readonly string[] = ['vike', 'vite-plugin-ssr', '@tanstack/react-start', '@tanstack/solid-start', '@tanstack/start', '@solidjs/start', '@analogjs/platform',
  '@builder.io/qwik-city', 'waku', '@react-router/dev', '@react-router/node', '@react-router/serve', 'vinxi', '@hono/vite-dev-server', '@sveltejs/adapter-node', 'express', 'nitro',
  // fix round 1 (review J2 I3): runtimes of serverless functions and Workers built next to a static site (each runs code on a server)
  '@cloudflare/vite-plugin', '@cloudflare/workers-types', '@cloudflare/next-on-pages', '@opennextjs/cloudflare', '@opennextjs/aws', '@netlify/functions', '@netlify/edge-functions',
  '@netlify/vite-plugin', '@vercel/node', '@vercel/functions', 'firebase-functions', 'firebase-admin', 'itty-router', 'serverless', 'serverless-http', '@vendia/serverless-express', '@types/aws-lambda'];
/**
 * Fix round 1 (review J2 I2): project files of another language's app (at the service folder's root): a Ruby, PHP, Java, Rust, Elixir or .NET
 * app, or a Procfile's web process, next to a static build is a server pipegen doesn't read. Python and Go come in through alsoLanguages.
 */
const OTHER_APP_FILES: readonly string[] = ['Procfile', 'Gemfile', 'config.ru', 'composer.json', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'Cargo.toml', 'mix.exs', 'manage.py', 'app.yaml'];
const OTHER_APP_EXT = /\.(?:csproj|fsproj)$/;
/**
 * Fix round 1 (review J2 I3): host configs that add server code to a static site, at the service folder's root, each with the line that says
 * so. A Pages-only wrangler config (pages_build_output_dir, no `main`) and a hosting-only firebase.json don't count. Read as text, one line at
 * a time: a match inside a comment counts too (the safe direction).
 */
const HOST_SERVER_CONFIGS: readonly { file: string; re: RegExp; what: string }[] = [
  { file: 'wrangler.toml', re: /^\s*main\s*=/, what: 'a Worker entry (main)' },
  { file: 'wrangler.json', re: /"main"\s*:/, what: 'a Worker entry (main)' },
  { file: 'wrangler.jsonc', re: /"main"\s*:/, what: 'a Worker entry (main)' },
  { file: 'netlify.toml', re: /^\s*(?:\[\[?\s*)?(?:edge_)?functions\b/, what: 'Netlify functions' },
  { file: 'vercel.json', re: /"(?:functions|builds)"\s*:/, what: 'Vercel functions' },
  { file: 'firebase.json', re: /"(?:functions|function|run)"\s*:/, what: 'Firebase functions or a Cloud Run rewrite' },
];
/** Astro adapter packages: the official ones by name, and any package whose name says it is an Astro adapter. */
const ASTRO_ADAPTER_DEP = /^@astrojs\/(?:node|vercel|netlify|cloudflare|deno)$|astro.*adapter|adapter.*astro|^astro-sst$/;
const GATSBY_ADAPTER_DEP = /^gatsby-adapter-/;

/** Server route and function folders (repo-relative inside the service), for every generator. */
const ROUTE_RES: readonly RegExp[] = [
  /^(?:src\/)?pages\/api\/.+/,
  /^(?:src\/)?app\/(?:.+\/)?route\.(?:js|jsx|ts|tsx|mjs|mts|cjs|cts)$/,
  /^(?:src\/)?middleware\.(?:js|jsx|ts|tsx|mjs|mts|cjs|cts)$/,
  /^api\/.+\.(?:js|jsx|ts|tsx|mjs|mts|cjs|cts|py|go|rb)$/,
  /^functions\/.+\.(?:js|jsx|ts|tsx|mjs|mts|cjs|cts|py)$/,
  /^netlify\/(?:edge-)?functions\/.+/,
  /(?:^|\/)_worker\.js(?:$|\/)/, // a Pages advanced-mode Worker, wherever the build copies it from
];
const NEXT_ROUTE_RES: readonly RegExp[] = [/^(?:src\/)?proxy\.(?:js|jsx|ts|tsx|mjs|mts|cjs|cts)$/];
const GATSBY_ROUTE_RES: readonly RegExp[] = [/^src\/api\/.+/];
/** Code that starts a server. Case-sensitive, linear, one line at a time. */
const SERVER_CODE_RE = /\b(?:createServer|createSecureServer)\s*\(|\.listen\s*\(|\b(?:Bun|Deno)\.serve\s*\(/;
const GATSBY_SSR_RE = /\bgetServerData\b/;

// ---------- evidence wording ----------

const shown = (rel: string, fallback: string) => (PLAIN_PATH_RE.test(rel) ? rel : fallback);
const UNSURE_TAIL = 'so pipegen treats it as a server (use --type static-site if it is)';
/** Fix round 2: the same tail where the unsure → server rule doesn't apply (a library, or a folder that isn't standalone). */
const UNSURE_TAIL_NOT_SERVER = "so pipegen doesn't treat it as a static site (use --type static-site if it is)";

// ---------- parsing a config ----------

// A parsed node: acorn's ESTree shapes, read by field name. Every field is checked where it is read.
interface N { type: string; [k: string]: any }   // eslint-disable-line @typescript-eslint/no-explicit-any
const isNode = (v: unknown): v is N => typeof v === 'object' && v !== null && typeof (v as { type?: unknown }).type === 'string';
class TooDeep extends Error {}

function walk(n: N, visit: (n: N) => void, depth = 0): void {
  if (depth > MAX_DEPTH) throw new TooDeep();
  visit(n);
  for (const k of Object.keys(n)) {
    if (k === 'type' || k === 'start' || k === 'end' || k === 'loc' || k === 'range') continue;
    const v: unknown = n[k];
    if (Array.isArray(v)) { for (const x of v) if (isNode(x)) walk(x, visit, depth + 1); } else if (isNode(v)) walk(v, visit, depth + 1);
  }
}

/** The program of a config file, or null when it can't be read as code (too big, not JavaScript or TypeScript, too deep). */
function parseConfig(text: string, rel: string): { program: N; nodes: N[] } | null {
  if (text.length > MAX_CONFIG_BYTES) return null;
  let code = text;
  if (/\.(?:ts|mts|cts)$/.test(rel)) {
    // sucrase drops a `namespace` or `module` block silently, where TypeScript would run its code: such a file is not read (as test-rules.ts)
    if (/\bnamespace\b|\bmodule\s+[A-Za-z_$"'`]/.test(text)) return null;
    try { code = transform(text, { transforms: ['typescript'], disableESTransforms: true, keepUnusedImports: true, filePath: rel }).code; } catch { return null; }
  }
  for (const sourceType of ['module', 'script'] as const) {
    let program: N;
    try { program = parse(code, { ecmaVersion: 'latest', sourceType, allowHashBang: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: sourceType === 'script' }) as unknown as N; } catch { continue; }
    const nodes: N[] = [];
    try { walk(program, (n) => nodes.push(n)); } catch { return null; }
    return { program, nodes };
  }
  return null;
}

/** The plain name of a property key: an identifier (not computed) or a string literal; null for a computed key. */
function keyName(p: N): string | null {
  if (p.computed === true) return null;
  if (isNode(p.key) && p.key.type === 'Identifier') return p.key.name as string;
  if (isNode(p.key) && p.key.type === 'Literal' && typeof p.key.value === 'string') return p.key.value;
  return null;
}
/** A string written out in one piece: a string literal or a template without `${}`. */
function literalString(n: unknown): string | undefined {
  if (!isNode(n)) return undefined;
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  if (n.type === 'TemplateLiteral' && Array.isArray(n.expressions) && n.expressions.length === 0) {
    const cooked: unknown = (n.quasis as N[] | undefined)?.[0]?.value?.cooked;
    return typeof cooked === 'string' ? cooked : undefined;
  }
  return undefined;
}
const isIdent = (n: unknown, name?: string): n is N & { type: 'Identifier' } => isNode(n) && n.type === 'Identifier' && (name === undefined || n.name === name);
const isModuleExports = (n: unknown): boolean => isNode(n) && n.type === 'MemberExpression' && n.computed !== true && isIdent(n.object, 'module') && isIdent(n.property, 'exports');

/** Every write to a member called `name` (`x.output = …`, `x['output'] = …`, `delete x.output`, `x.output++`), or to a computed member. */
function writesMember(nodes: readonly N[], names: readonly string[]): boolean {
  const target = (t: unknown) => isNode(t) && t.type === 'MemberExpression'
    && (t.computed === true ? literalString(t.property) === undefined || names.includes(literalString(t.property) as string) : isIdent(t.property) && names.includes(t.property.name as string));
  return nodes.some((n) => (n.type === 'AssignmentExpression' && target(n.left)) || (n.type === 'UpdateExpression' && target(n.argument))
    || (n.type === 'UnaryExpression' && n.operator === 'delete' && target(n.argument)));
}

/**
 * Whether the file uses one of the handles that reach a CommonJS module's own exports or Node's module cache: `arguments` or `this` (the
 * module wrapper's exports and module), require used as a value (require.cache), the module built-in, and the members mainModule, cache,
 * _cache, getBuiltinModule, constructor, prototype and __proto__, or eval and Function. Defense in depth for the 'export' verdict only: a miss
 * here can only drop a DAST recommendation the repo's own config hid from pipegen, and the verdict needs the literal export besides.
 */
const REACH_MEMBERS: ReadonlySet<string> = new Set(['mainModule', 'cache', '_cache', 'getBuiltinModule', 'constructor', 'prototype', '__proto__']);
function reachesModuleHandles(nodes: readonly N[]): boolean {
  const callees = new Set(nodes.filter((n) => n.type === 'CallExpression').map((n) => n.callee as unknown));
  return nodes.some((n) => n.type === 'ThisExpression' || isIdent(n, 'arguments') || isIdent(n, 'eval') || isIdent(n, 'Function')
    || (isIdent(n, 'require') && !callees.has(n))
    || (n.type === 'MemberExpression' && (n.computed === true ? literalString(n.property) === undefined || REACH_MEMBERS.has(literalString(n.property) as string) : isIdent(n.property) && REACH_MEMBERS.has(n.property.name as string)))
    || (n.type === 'Literal' && (n.value === 'module' || n.value === 'node:module')));
}

/**
 * Whether the file can reach code of the repo's own (and so, through a cycle, its own exported object): an import, a re-export or a require
 * of a relative or absolute path, any dynamic import(), or a require of something that isn't a plain string.
 */
function importsLocalCode(nodes: readonly N[]): boolean {
  const local = (src: unknown) => { const v = literalString(src); return v === undefined || v.startsWith('.') || v.startsWith('/') || /^[A-Za-z]:/.test(v) || v.startsWith('file:'); };
  return nodes.some((n) => ((n.type === 'ImportDeclaration' || n.type === 'ExportNamedDeclaration' || n.type === 'ExportAllDeclaration') && isNode(n.source) && local(n.source))
    || n.type === 'ImportExpression'
    || (n.type === 'CallExpression' && isIdent(n.callee, 'require') && (!Array.isArray(n.arguments) || n.arguments.length !== 1 || local(n.arguments[0]))));
}

/**
 * The one value a config file exports by default: `export default X` or `module.exports = X` (exactly one of them, once). An identifier is
 * followed through one top-level `const` that no other code names. `unwrap` names wrapper calls that may be looked through (`defineConfig`).
 * null when the export can't be followed that way.
 */
function defaultExport(program: N, nodes: readonly N[], unwrap: readonly string[] = []): N | null | 'none' {
  const exports: N[] = [];
  for (const st of program.body as N[]) {
    if (st.type === 'ExportDefaultDeclaration' && isNode(st.declaration)) exports.push(st.declaration);
    else if (st.type === 'ExportNamedDeclaration' && Array.isArray(st.specifiers) && (st.specifiers as N[]).some((sp) => isNode(sp.exported) && (sp.exported.name === 'default' || sp.exported.value === 'default'))) return null;
    else if (st.type === 'ExportAllDeclaration') return null;
  }
  // module.exports counts only as a plain top-level statement: one inside an `if`, a function or an expression may not run
  const topLevel = (program.body as N[]).filter((st) => st.type === 'ExpressionStatement' && isNode(st.expression) && st.expression.type === 'AssignmentExpression'
    && st.expression.operator === '=' && isModuleExports(st.expression.left)).map((st) => st.expression as N);
  for (const a of topLevel) exports.push(a.right as N);
  // a second use of `module` (Object.assign(module.exports, …), module.exports.output = …) could change what it holds
  const moduleUses = nodes.filter((n) => isIdent(n, 'module')).length;
  if (exports.length === 0) return moduleUses > 0 ? null : 'none';
  if (exports.length > 1) return null;
  if (moduleUses > 1) return null;
  let value = exports[0] as N;
  const follow = (v: N): N | null => {
    if (!isIdent(v)) return v;
    const name = v.name as string;
    // exactly two mentions of the name: its declaration and the export
    if (nodes.filter((n) => isIdent(n, name)).length !== 2) return null;
    for (const st of program.body as N[]) {
      if (st.type !== 'VariableDeclaration' || st.kind !== 'const') continue;
      for (const d of st.declarations as N[]) if (isIdent(d.id, name) && isNode(d.init)) return d.init;
    }
    return null;
  };
  const followed = follow(value);
  if (followed === null) return null;
  value = followed;
  if (value.type === 'CallExpression' && isIdent(value.callee) && unwrap.includes(value.callee.name as string) && Array.isArray(value.arguments) && value.arguments.length === 1 && isNode(value.arguments[0])) {
    const inner = follow(value.arguments[0] as N);
    if (inner === null) return null;
    value = inner;
  }
  return value;
}

/** The `output` properties of an object literal, or null when it has a spread, a computed key, or isn't an object literal. */
function plainObject(v: N): N[] | null {
  if (v.type !== 'ObjectExpression') return null;
  for (const p of v.properties as N[]) if (p.type !== 'Property' || keyName(p) === null) return null;
  return v.properties as N[];
}

type NextOutput = 'export' | 'other' | 'none' | 'unclear';
/** What a parsed next.config sets `output` to (rule in the file comment). */
function nextOutput(parsed: { program: N; nodes: N[] }): NextOutput {
  const { program, nodes } = parsed;
  const mentions = nodes.filter((n) => n.type === 'Property' && (n.computed === true || keyName(n) === 'output')).length;
  const value = defaultExport(program, nodes);
  if (value === 'none') return mentions > 0 ? 'unclear' : 'none';
  if (value === null) return mentions > 0 ? 'unclear' : 'none';
  const props = plainObject(value);
  if (props === null) return mentions > 0 || value.type === 'ObjectExpression' ? 'unclear' : 'none';
  const outputs = props.filter((p) => keyName(p) === 'output');
  if (outputs.length === 0) return mentions > 0 ? 'unclear' : 'none';
  if (outputs.length > 1) return 'unclear';
  const out = outputs[0] as N;
  if (out.kind !== 'init' || out.method === true) return 'unclear';
  const literal = literalString(out.value);
  if (literal === undefined) return 'unclear';
  if (literal !== 'export') return 'other';
  // nothing else may change it: the name `output` appears once in the whole file (that key), nothing writes a computed member, and the file
  // can't reach its own exported object through an import of the repo's code (a self-import, or a local file re-exporting it)
  const named = nodes.filter((n) => isIdent(n, 'output') || (n.type === 'Literal' && n.value === 'output')).length;
  return mentions === 1 && named === 1 && !writesMember(nodes, ['output']) && !importsLocalCode(nodes) && !reachesModuleHandles(nodes) ? 'export' : 'unclear';
}

type AstroOutput = 'static' | 'server' | 'unclear';
/** What a parsed astro.config gives: static (the default), server (a server output, an adapter), or unclear. */
function astroOutput(parsed: { program: N; nodes: N[] }): AstroOutput {
  const { program, nodes } = parsed;
  if (nodes.some((n) => (n.type === 'Property' && keyName(n) === 'adapter') || isIdent(n, 'setAdapter') || isIdent(n, 'adapter'))) return 'server';
  const outputs = nodes.filter((n) => n.type === 'Property' && keyName(n) === 'output');
  for (const o of outputs) {
    const literal = literalString(o.value);
    if (literal === 'server' || literal === 'hybrid') return 'server';
  }
  const value = defaultExport(program, nodes, ['defineConfig']);
  if (value === null || value === 'none') return 'unclear';
  if (plainObject(value) === null) return 'unclear';
  if (outputs.some((o) => literalString(o.value) !== 'static' || o.kind !== 'init')) return 'unclear';
  if (writesMember(nodes, ['output', 'adapter'])) return 'unclear';
  // fix round 1 (review J2 minor 2): the module handles of the Next.js verdict, a dynamic import, and an import of the config file itself (a
  // local import of a plugin stays fine: Astro configs often import their own remark or vite plugins)
  const selfImport = nodes.some((n) => n.type === 'ImportExpression' || ((n.type === 'ImportDeclaration' || n.type === 'ExportNamedDeclaration' || n.type === 'ExportAllDeclaration')
    && isNode(n.source) && /(?:^|\/)astro\.config(?:\.[a-z]+)?$/.test(literalString(n.source) ?? 'astro.config')));
  if (selfImport || reachesModuleHandles(nodes)) return 'unclear';
  return 'static';
}

// ---------- the static decision ----------

interface StaticResult { isStatic: boolean; unsure: boolean; evidence: string[] }
const notStatic = (evidence: string[] = []): StaticResult => ({ isStatic: false, unsure: false, evidence });

const scriptText = (k: TypeInput, name: string): string => asString(k.scripts[name]) ?? '';
/** The `&&` / `;` parts of a script, trimmed. */
const parts = (text: string): string[] => (text.length > 2000 || !regexSafe(text) ? [] : text.split(/&&|;|\|\|/).map((t) => t.trim()).filter((t) => t !== ''));

/** The configs of one generator in the service's own folder. */
function configsOf(k: TypeInput, base: string): string[] {
  return CONFIG_EXTS.map((e) => inDir(k.dir, `${base}.${e}`)).filter((f) => k.fileSet.has(f));
}

/** The generator's own signal: static, not static, or unsure (with its evidence). */
async function generatorSignal(k: TypeInput, g: { gen: Gen; label: string }): Promise<StaticResult> {
  const readConfig = async (rel: string) => {
    const text = await k.read(rel);
    return text === null ? null : parseConfig(text, rel);
  };
  const unsure = (line: string): StaticResult => ({ isStatic: false, unsure: true, evidence: [line] });
  switch (g.gen) {
    case 'next': {
      const configs = configsOf(k, 'next.config');
      if (configs.length === 0) return notStatic(); // a Next.js app with no config is a server app
      if (configs.length > 1) return unsure(`two or more Next.js config files (${configs.map((c) => shown(c, 'a file')).join(', ')}): pipegen can't tell which one Next.js reads, ${UNSURE_TAIL}`);
      const rel = configs[0] as string;
      const parsed = await readConfig(rel);
      if (parsed === null) return unsure(`pipegen couldn't read ${shown(rel, 'the Next.js config')} as code, ${UNSURE_TAIL}`);
      const out = nextOutput(parsed);
      if (out === 'export') return { isStatic: true, unsure: false, evidence: [`output: "export" in ${shown(rel, 'the Next.js config')}`] };
      if (out === 'unclear') return unsure(`looks like a static site, but \`output\` isn't a plain 'export' in ${shown(rel, 'the Next.js config')}, ${UNSURE_TAIL}`);
      return notStatic();
    }
    case 'astro': {
      const names = new Set([...Object.keys(k.deps), ...Object.keys(k.devDeps)]);
      if ([...names].some((d) => regexSafe(d) && ASTRO_ADAPTER_DEP.test(d))) return notStatic(['an Astro adapter package in package.json (renders pages on a server)']);
      const configs = configsOf(k, 'astro.config');
      if (configs.length === 0) return { isStatic: true, unsure: false, evidence: ['Astro with no config file (a static build by default)'] };
      if (configs.length > 1) return unsure(`two or more Astro config files: pipegen can't tell which one Astro reads, ${UNSURE_TAIL}`);
      const rel = configs[0] as string;
      const parsed = await readConfig(rel);
      if (parsed === null) return unsure(`pipegen couldn't read ${shown(rel, 'the Astro config')} as code, ${UNSURE_TAIL}`);
      const out = astroOutput(parsed);
      if (out === 'server') return notStatic([`a server output or an adapter in ${shown(rel, 'the Astro config')}`]);
      if (out === 'unclear') return unsure(`looks like a static Astro site, but pipegen can't read its output and adapter in ${shown(rel, 'the Astro config')}, ${UNSURE_TAIL}`);
      return { isStatic: true, unsure: false, evidence: [`Astro with no server output and no adapter in ${shown(rel, 'the Astro config')}`] };
    }
    case 'vite': {
      if (!parts(scriptText(k, 'build')).some((t) => VITE_BUILD.test(t))) return notStatic();
      return { isStatic: true, unsure: false, evidence: ['Vite builds the site (the build script runs vite build)'] };
    }
    case 'gatsby': {
      const names = new Set([...Object.keys(k.deps), ...Object.keys(k.devDeps)]);
      if ([...names].some((d) => regexSafe(d) && GATSBY_ADAPTER_DEP.test(d))) return unsure(`a Gatsby adapter package in package.json, ${UNSURE_TAIL}`);
      for (const rel of configsOf(k, 'gatsby-config')) {
        const text = await k.read(rel);
        if (text === null || regexLines(text).some((l) => /\badapter\b/.test(l))) return unsure(`an adapter (or an unreadable config) in ${shown(rel, 'the Gatsby config')}, ${UNSURE_TAIL}`);
      }
      return { isStatic: true, unsure: false, evidence: ['Gatsby (in package.json) builds a static site'] };
    }
    default:
      return { isStatic: true, unsure: false, evidence: [`${g.label} (in package.json) builds a static site`] };
  }
}

/** The server signs of a service that a generator says is static (rules in the file comment). Each is one evidence line. */
async function serverSigns(k: TypeInput, g: { gen: Gen; pkg: string; label: string }): Promise<string[]> {
  const signs: string[] = [];
  const names = new Set([...Object.keys(k.deps), ...Object.keys(k.devDeps)]);
  for (const d of [...SERVER_DEPS, ...SSR_DEPS]) if (d !== g.pkg && names.has(d) && !signs.some((x) => x.startsWith(`${d} `))) signs.push(`${d} in package.json (a server package)`);
  if (g.gen === 'astro' && [...names].some((d) => regexSafe(d) && ASTRO_ADAPTER_DEP.test(d))) signs.push('an Astro adapter package in package.json');
  if (k.listingIncomplete === true) signs.push("pipegen listed only part of the files (a read limit), so it couldn't check them all for a server");
  for (const l of k.alsoLanguages ?? []) signs.push(`another language's app in the same folder (${l === 'python' ? 'Python' : l === 'go' ? 'Go' : 'another language'})`);
  const otherApp = [...OTHER_APP_FILES.map((f) => inDir(k.dir, f)).filter((f) => k.fileSet.has(f)),
    ...[...k.fileSet].filter((f) => f.startsWith(k.dir === '.' ? '' : `${k.dir}/`) && !f.slice(k.dir === '.' ? 0 : k.dir.length + 1).includes('/') && OTHER_APP_EXT.test(f))].sort();
  if (otherApp.length > 0) signs.push(`another language's app in the same folder (${otherApp.slice(0, 3).map((f) => shown(f, 'a file')).join(', ')})`);
  for (const c of HOST_SERVER_CONFIGS) {
    const rel = inDir(k.dir, c.file);
    if (!k.fileSet.has(rel)) continue;
    const text = await k.read(rel);
    if (text === null) signs.push(`pipegen couldn't read ${shown(rel, 'a host config')} to check it for server code`);
    else if (text.split(/\r?\n/).some((l) => !regexSafe(l) || c.re.test(l))) signs.push(`${c.what} in ${shown(rel, 'a host config')}`);
  }
  for (const name of RUN_SCRIPTS) {
    if (!Object.hasOwn(k.scripts, name)) continue;
    const ps = parts(scriptText(k, name));
    if (ps.length === 0 || !ps.every((t) => OWN_COMMAND[g.gen].test(t))) signs.push(`the ${name} script runs something other than ${g.label}'s own command`);
  }
  const skip = k.untrackedIgnored === undefined ? () => false : await k.untrackedIgnored();
  const deeper = k.serviceDirs.filter((o) => o !== k.dir && (k.dir === '.' || o.startsWith(`${k.dir}/`)));
  const under = (f: string, d: string) => d === '.' || f.startsWith(`${d}/`);
  const owned = [...k.fileSet].filter((f) => under(f, k.dir) && !deeper.some((o) => under(f, o)) && !skip(f)).sort();
  const relTo = (f: string) => (k.dir === '.' ? f : f.slice(k.dir.length + 1));
  const routes = [...ROUTE_RES, ...(g.gen === 'next' ? NEXT_ROUTE_RES : []), ...(g.gen === 'gatsby' ? GATSBY_ROUTE_RES : [])];
  const route = owned.find((f) => regexSafe(f) && routes.some((re) => re.test(relTo(f))));
  if (route !== undefined) signs.push(`a server route or function: ${shown(route, 'a file')}`);
  // the generator's own config at the service root isn't app code (minor 3: only there; a config deeper in the tree is scanned)
  const code = owned.filter((f) => CODE_FILE_RE.test(f) && !isTestFile(relTo(f)) && !(!relTo(f).includes('/') && /^(?:next|astro|vite|gatsby-config|docusaurus|vitepress)\.config\./.test(baseOf(f))));
  if (code.length > MAX_SIGNAL_FILES) {
    signs.push(`more than ${MAX_SIGNAL_FILES.toLocaleString('en-US')} code files: pipegen couldn't check them all for a server`);
    return signs;
  }
  let bytes = 0;
  let port: string | undefined;
  let server: string | undefined;
  let ssr: string | undefined;
  let unread: string | undefined;
  let longLines: string | undefined;
  for (const f of code) {
    if (port !== undefined && server !== undefined && (g.gen !== 'gatsby' || ssr !== undefined)) break;
    const text = await k.read(f);
    // fix round 1 (review J2 I1): code pipegen couldn't read, or lines too long to check, could hold a server: never "no server sign"
    if (text === null) { unread ??= f; continue; }
    if (longLines === undefined && text.split(/\r?\n/).some((l) => !regexSafe(l))) longLines = f;
    bytes += text.length;
    if (bytes > MAX_SIGNAL_BYTES) {
      signs.push("too much code to read: pipegen couldn't check it all for a server");
      break;
    }
    for (const line of regexLines(text)) {
      if (port === undefined && PORT_RULES.some((r) => r.test(line))) port = f;
      if (server === undefined && SERVER_CODE_RE.test(line)) server = f;
      if (g.gen === 'gatsby' && ssr === undefined && GATSBY_SSR_RE.test(line)) ssr = f;
    }
  }
  if (unread !== undefined) signs.push(`pipegen couldn't read ${shown(unread, 'a code file')} (too large or not a regular file) to check it for a server`);
  if (longLines !== undefined) signs.push(`${shown(longLines, 'a code file')} has lines too long for pipegen to check for a server`);
  if (port !== undefined) signs.push(`a port default in ${shown(port, 'a code file')}`);
  if (server !== undefined) signs.push(`code that starts a server in ${shown(server, 'a code file')}`);
  if (ssr !== undefined) signs.push(`server-rendered pages (getServerData) in ${shown(ssr, 'a code file')}`);
  return signs;
}

async function staticDecision(k: TypeInput): Promise<StaticResult> {
  const names = new Set([...Object.keys(k.deps), ...Object.keys(k.devDeps)]);
  const g = GENERATORS.find((x) => names.has(x.pkg));
  if (g === undefined) return notStatic();
  const signal = await generatorSignal(k, g);
  if (!signal.isStatic) return signal;
  const signs = await serverSigns(k, g);
  if (signs.length === 0) return signal;
  return { isStatic: false, unsure: true, evidence: [...signal.evidence, ...signs, `looks like a static site, but it has the server signs above, ${UNSURE_TAIL}`] };
}

// ---------- phase 1 and 2 ----------

const ordered = (types: Iterable<ServiceType>): ServiceType[] => { const set = new Set(types); return SERVICE_TYPES.filter((t) => set.has(t)); };
const hasBin = (m: Obj): boolean => asString(m.bin) !== undefined || Object.values(asObj(m.bin)).some((v) => asString(v) !== undefined);

/**
 * Phase 1 (ruling B2), in readService: the type from the service's own files. Node services get the static decision, `library` (exports, main
 * or module with no run script and no framework), `cli` (bin) and `container` (a Dockerfile); other languages get `container` only, and
 * finishProjectTypes adds `server` from today's rule (#121 scope: type detection is Node-only in v0.2), with `unsure: false`.
 */
export async function projectTypeOf(k: TypeInput): Promise<ProjectType> {
  const types: ServiceType[] = [];
  const evidence: string[] = [];
  let unsure = false;
  if (k.language === 'node') {
    const decision = await staticDecision(k);
    if (decision.isStatic) types.push('static-site');
    unsure = decision.unsure;
    evidence.push(...decision.evidence);
    const runs = RUN_SCRIPTS.some((n) => Object.hasOwn(k.scripts, n));
    const entry = ['exports', 'main', 'module'].filter((f) => k.manifest[f] !== undefined && k.manifest[f] !== null);
    if (entry.length > 0 && !runs && k.frameworks.length === 0) {
      types.push('library');
      evidence.push(`${entry.join(', ')} in package.json, and no start, dev or serve script`);
    }
    if (hasBin(k.manifest)) {
      types.push('cli');
      evidence.push('bin in package.json');
    }
  }
  if (k.hasDockerfile) {
    types.push('container');
    evidence.push(`has a Dockerfile: ${shown(inDir(k.dir, 'Dockerfile'), 'Dockerfile')}`);
  }
  return { types: ordered(types), evidence, unsure };
}

const HOST_WORDS: Readonly<Record<StaticHost, string>> = {
  'cloudflare-pages': 'wrangler pages deploy', netlify: 'netlify deploy', 'github-pages': 'GitHub Pages', 'firebase-hosting': 'firebase deploy --only hosting',
};

/** The evidence line of baseRunnable's facts (fixed wording; framework names come from pipegen's own list). */
function serverLine(s: Service): string {
  const facts: string[] = [];
  for (const n of RUN_SCRIPTS) if (s.scripts.includes(n)) facts.push(`a ${n} script`);
  for (const f of s.frameworks) if (/^[a-z@/.-]{1,40}$/.test(f)) facts.push(`the ${f} framework`);
  if (s.port !== undefined && s.publishedPackage !== true) facts.push(`port ${s.port}`);
  if ((s.dockerfile ?? '') !== '') facts.push('a Dockerfile');
  return `runs as a server: ${facts.join(', ')}`;
}

/**
 * Phase 2 (ruling B2), after readWorkflows and publishedPackage: `library` for a published package; `server` when baseRunnable holds and the
 * service isn't static (ruling S1), or when the static decision ended unsure (an unsure static site is a server, even with no run script),
 * except for a folder that isn't standalone (notStandalone) or has library evidence, which stays as it was before J2; for each static site,
 * one evidence line per workflow that deploys to a static host. Changes the services in place; a service without projectType gets one.
 */
export function finishProjectTypes(services: Service[], workflows: readonly ExistingWorkflow[]): void {
  const hostLines = workflows.filter((w) => (w.staticHosts?.length ?? 0) > 0)
    .map((w) => `deploys with ${(w.staticHosts as StaticHost[]).map((h) => HOST_WORDS[h]).join(' and ')} (${shown(w.path, 'a workflow')})`);
  const publishers = workflows.filter((w) => (w.publishes?.length ?? 0) > 0).map((w) => shown(w.path, 'a workflow'));
  for (const s of services) {
    const t: ProjectType = s.projectType ?? { types: [], evidence: [], unsure: false };
    const types = new Set(t.types);
    const evidence = [...t.evidence];
    if (s.publishedPackage === true && !types.has('library')) {
      types.add('library');
      evidence.push(`published as a package by ${publishers.length > 0 ? publishers.join(', ') : 'a workflow'}`);
    }
    if (!types.has('static-site') && baseRunnable(s)) {
      if (!types.has('server')) evidence.push(serverLine(s));
      types.add('server');
    } else if (!types.has('static-site') && t.unsure && !types.has('server')) {
      if (s.notStandalone === undefined && !types.has('library')) {
        // controller ruling (review J2 ⚠️1): an unsure static site is a server, even with no run script (#121: the stricter type wins)
        types.add('server');
        evidence.push("treated as a server: pipegen isn't sure it is a static site");
      } else {
        // fix round 2 (review J2 r1 N1; controller ruling): a folder that isn't standalone (P55) or that has library evidence keeps what it
        // was before J2 (not runnable); only the unsure line's wording changes, so it doesn't claim a server
        for (let i = 0; i < evidence.length; i++) evidence[i] = (evidence[i] as string).replace(UNSURE_TAIL, UNSURE_TAIL_NOT_SERVER);
      }
    }
    if (types.has('static-site')) evidence.push(...hostLines);
    s.projectType = { types: ordered(types), evidence: [...new Set(evidence)], unsure: t.unsure, ...(t.overridden === true ? { overridden: true as const } : {}) };
  }
}

/** J1's rule for reading signals: a path is left out only when git ignores it AND git's index is known and doesn't list it. Unsure → kept. */
export async function untrackedIgnoredOf(dir: string): Promise<(rel: string) => boolean> {
  const index = await readGitIndexPaths(dir);
  if (index === null) return () => false;
  const ignore = await loadIgnore(dir, { whenUnsure: 'not-ignored' });
  return (rel) => !index.has(rel) && ignore.ignored(rel);
}

// ---------- overrides ----------

/**
 * `--type` and the type prompt (J5; ruling S14): each override replaces the service's types other than `container`, which stays while the
 * service has a Dockerfile (so a click can't drop its image scans). `service: null` names the repo's only service. Returns a new profile; throws
 * an Error with a plain-English message for an unknown name, a bare type on a repo with several services, or one service named twice.
 */
export function applyTypeOverrides<P extends Pick<RepoProfile, 'services'>>(p: P, o: readonly TypeOverride[]): P {
  if (o.length === 0) return p;
  const chosen = new Map<number, ServiceType>();
  for (const { service, type } of o) {
    if (!SERVICE_TYPES.includes(type)) throw new Error(`Unknown type ${safeText(String(type), 40)}: use one of ${SERVICE_TYPES.join(', ')}.`);
    let i: number;
    if (service === null) {
      if (p.services.length !== 1) throw new Error(`This repo has ${p.services.length} services, so a type needs the service's name: use --type <service>=<type> (services: ${p.services.map((s) => safeText(s.name, 60)).join(', ') || 'none'}).`);
      i = 0;
    } else {
      i = p.services.findIndex((s) => s.name === service);
      if (i < 0) throw new Error(`No service is named ${safeText(service, 60)} (services: ${p.services.map((s) => safeText(s.name, 60)).join(', ') || 'none'}).`);
    }
    if (chosen.has(i)) throw new Error(`The service ${safeText((p.services[i] as Service).name, 60)} was given a type twice; give each service one type.`);
    chosen.set(i, type);
  }
  return {
    ...p,
    services: p.services.map((s, i) => {
      const type = chosen.get(i);
      if (type === undefined) return s;
      const keepContainer = (s.dockerfile ?? '') !== '';
      const before = s.projectType ?? { types: [], evidence: [], unsure: false };
      return {
        ...s,
        projectType: {
          types: ordered([type, ...(keepContainer ? ['container' as const] : [])]),
          evidence: [...before.evidence, `set to ${type} by you`],
          unsure: false,
          overridden: true,
        },
      };
    }),
  };
}
