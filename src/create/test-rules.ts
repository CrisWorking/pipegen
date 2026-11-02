// The rules for AI-written starter tests (v0.2 Plan D, D7; preflight S9, item 9). A leaf: the creator (src/create/tests.ts), the referee's judge
// (src/engine/created-judges/tests.ts) and the guard all call analyzeTestFile / starterTestFileProblems, so what the creator delivers is exactly
// what the judges accept.
//
// The AI's test file runs in the user's CI, so it is hostile input. This is NOT a denylist of words (`require('child' + '_process')`, `import(x)`,
// `eval` and `process.binding` walk straight past one). The file is PARSED (acorn; TypeScript is first reduced to JavaScript with sucrase) and the
// syntax tree is walked:
//   imports      every import, `export ... from`, `require()` and `import()` has a string-literal specifier that is on the allowlist: `vitest` (named
//                imports from a fixed set, no alias), node:assert, node:assert/strict, node:test, node:path, node:url, node:util, node:http, a relative
//                path that stays inside the service, or a name in the service's own `dependencies`. Nothing else.
//   code reach   eval, Function, globalThis and friends, Reflect, module, `require` used as a value, `process` other than a few reads, import.meta
//                other than url/dirname/filename, `.constructor`, `__proto__` and the other ways to get at the Function constructor are refused,
//                computed forms (`globalThis['ev' + 'al']`) included when the key can be read statically, and a computed key that can not be read
//                statically is refused too (anything not statically decidable is refused). The only `vi` helpers are fixed (no vi.mock, importActual).
//   not skipped  `.skip`, `.only`, `.todo`, `.skipIf`, `.runIf`, `.fails`, `.each`, `xit`, `fit`, ... and the same names as options are refused.
//   assertions   a test is `it('name', () => {...})` written in the file or in `describe`, never in a loop or a condition; each test needs an
//                assertion written directly in its body (`expect(x).matcher(...)` or an assert call; one on a literal does not count).
//   urls         a string with `scheme://host` may only name localhost, 127.0.0.1 or example.com (a host that is not static is refused).
//   globals      (security scan) calls and member access on globals are an ALLOWLIST, not a list of bad names: a test may use
//                  - the imports of the allowed modules, expect, assert calls, and the vitest API: describe, it, test, the hooks, and vi.fn, vi.spyOn, vi.mock
//                    (a literal relative path only), the fake-timer helpers, vi.stubEnv;
//                  - JSON.parse and JSON.stringify; Math.*; Number.isInteger/isFinite/isNaN/isSafeInteger/parseFloat/parseInt and its constants; String.raw;
//                    Array.isArray/from/of; Object.keys/values/entries/assign/freeze/fromEntries/is/hasOwn; Promise.resolve/reject/all/allSettled/race/any/withResolvers;
//                    Date.now/UTC/parse; new URL(...) and the plain constructors (Map, Set, Error, Date, RegExp, typed arrays, Buffer ...); timers, console;
//                  - process.env, .cwd(), .platform, .nextTick, .hrtime, .uptime;
//                  and nothing else: a free name that is declared nowhere in the file and not on these lists is refused, so are Reflect, Symbol, Proxy, Function,
//                  globalThis and the reflection members of any object (getOwnPropertyDescriptor(s), getOwnPropertyNames/Symbols, getPrototypeOf, setPrototypeOf,
//                  defineProperty, fromCharCode ...). A computed key must fold to a plain name; one that can not be read statically is refused.
//   network      fetch, WebSocket, EventSource and XMLHttpRequest are refused. node:http: createServer, request, get, STATUS_CODES, METHODS only; request and get
//                  must name a literal local target (a string starting with http://127.0.0.1 or localhost, or an options object with a literal local host or none,
//                  e.g. the port of a server the test started with listen(0)). Joined strings (`'ht' + 'tp://x'`) are read whole before the URL check.
//   this         `this` in a plain (non-arrow, non-class) function is refused, and at the top of a script. A .js file is parsed by the service's package.json
//                  "type" ("module": as a module; otherwise both as a script and as a module, with the problems of each), .cjs as a script, .mjs/.ts as a module.
// A file that does not parse is refused. The real boundary stays the CI job (repo-code job, no pipegen secrets, egress block): this is the first layer.
//
// TypeScript caveat: sucrase silently drops a `namespace`/`module` block, which a real compiler would run, so a TypeScript file that has one is refused.
import { isBuiltin } from 'node:module';
import { posix } from 'node:path';
import { parse } from 'acorn';
import { transform } from 'sucrase';
import { activeSafeText } from '../util/known-values.js';

/** The fixed framework for Node services (ruling B2): the reviewed vitest. */
export const STARTER_FRAMEWORK = 'vitest';
export const STARTER_VITEST_VERSION = '5.0.5';
export const MAX_TEST_FILE_BYTES = 50 * 1024;
export const MAX_TEST_FILES = 20;
const MAX_PROBLEMS = 30;
const MAX_DEPTH = 400;

// ---------- paths ----------

const TEST_DIRS: readonly string[] = ['test', 'tests', '__tests__'];
const SEGMENT_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+@-]*$/;
const TEST_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+@-]*\.test\.(?:ts|js|mjs|cjs)$/;
const CODE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+@-]*\.(?:ts|js|mjs|cjs)$/;
const CONFIG_NAME_RE = /^(?:vitest|vite)\.(?:config|workspace)(?:\.|$)/i;
/** A file name (not a path) that is a starter test: `<name>.test.{ts,js,mjs,cjs}`. */
export const isTestName = (name: string): boolean => TEST_NAME_RE.test(name);

/** Why `rel` (a path inside the service) is not a path starter tests may use, or null. S9: `{test,tests,__tests__}/**` `/*.test.{ts,js,mjs,cjs}` and `test/helpers/**`. */
export function starterTestPathProblem(rel: string): string | null {
  const segs = rel.split('/');
  if (segs.length < 2) return 'starter tests go in a test, tests or __tests__ folder of the service';
  if (!TEST_DIRS.includes(segs[0] as string)) return 'starter tests go in a test, tests or __tests__ folder of the service';
  if (segs.some((s) => !SEGMENT_RE.test(s) || s === 'node_modules' || s === '..')) return 'the path has a hidden, vendored or unusual segment';
  const name = segs[segs.length - 1] as string;
  if (CONFIG_NAME_RE.test(name)) return 'a vitest or vite config file is never written (it is a protected path)';
  if (TEST_NAME_RE.test(name)) return null;
  if (segs[0] === 'test' && segs[1] === 'helpers' && segs.length >= 3 && CODE_NAME_RE.test(name)) return null;
  return 'a test file is named <name>.test.ts, .js, .mjs or .cjs (helpers go in test/helpers/)';
}

const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

/** The service whose folder holds `path` as a starter-test path (the deepest, when services nest): its root and the path inside it. Null when none. */
export function starterOwner(path: string, serviceRoots: readonly string[]): { root: string; rel: string } | null {
  let best: { root: string; rel: string } | null = null;
  for (const r0 of serviceRoots) {
    const root = rootPrefix(r0);
    if (root !== '' && !path.startsWith(`${root}/`)) continue;
    const rel = root === '' ? path : path.slice(root.length + 1);
    if (starterTestPathProblem(rel) !== null) continue;
    if (best === null || root.length > best.root.length) best = { root, rel };
  }
  return best;
}

/** The names under `dependencies` of a package.json text (valid npm names only); an unreadable text gives none (fail closed). */
export function dependencyNames(packageJson: string): string[] {
  try {
    const pkg = JSON.parse(packageJson) as unknown;
    const deps = typeof pkg === 'object' && pkg !== null ? (pkg as { dependencies?: unknown }).dependencies : undefined;
    if (typeof deps !== 'object' || deps === null || Array.isArray(deps)) return [];
    return Object.keys(deps).filter((n) => NPM_NAME_RE.test(n));
  } catch { return []; }
}
/** The module type of a package.json text: `module` only when "type" is exactly "module"; an unreadable text is `commonjs` (both readings are then checked). */
export function packageModuleType(packageJson: string): 'module' | 'commonjs' {
  try { const pkg = JSON.parse(packageJson) as { type?: unknown } | null; return typeof pkg === 'object' && pkg !== null && pkg.type === 'module' ? 'module' : 'commonjs'; } catch { return 'commonjs'; }
}
const NPM_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]{0,213}\/)?[a-z0-9][a-z0-9._-]{0,213}$/;

// ---------- the tables ----------

const ALLOWED_BUILTINS: ReadonlySet<string> = new Set(['vitest', 'node:assert', 'node:assert/strict', 'node:test', 'node:path', 'node:url', 'node:util', 'node:http']);
const ASSERT_MODULES: ReadonlySet<string> = new Set(['node:assert', 'node:assert/strict']);
const VITEST_NAMES: ReadonlySet<string> = new Set(['describe', 'it', 'test', 'expect', 'vi', 'beforeAll', 'afterAll', 'beforeEach', 'afterEach']);
const NODE_TEST_NAMES: ReadonlySet<string> = new Set(['describe', 'it', 'test', 'before', 'after', 'beforeEach', 'afterEach']);
const VI_OK: ReadonlySet<string> = new Set(['fn', 'spyOn', 'useFakeTimers', 'useRealTimers', 'advanceTimersByTime', 'advanceTimersToNextTimer', 'runAllTimers', 'runOnlyPendingTimers', 'setSystemTime', 'getMockedSystemTime', 'clearAllMocks', 'resetAllMocks', 'restoreAllMocks', 'isMockFunction', 'stubEnv', 'unstubAllEnvs', 'mock']);
const PROCESS_OK: ReadonlySet<string> = new Set(['env', 'cwd', 'platform', 'nextTick', 'hrtime', 'uptime']);
const META_OK: ReadonlySet<string> = new Set(['url', 'dirname', 'filename']);
/** Names that give code execution or a way around the checks. */
const BANNED_IDENT: ReadonlySet<string> = new Set(['eval', 'Function', 'globalThis', 'global', 'window', 'self', 'Reflect', 'WebAssembly', 'Worker', 'SharedWorker', 'module', 'XMLHttpRequest', 'importScripts',
  // the network and the reflection globals (security scan: no fetch or sockets of its own, no way to build a name at run time and reach code)
  'fetch', 'WebSocket', 'EventSource', 'Symbol', 'Proxy']);
const BANNED_PROP: ReadonlySet<string> = new Set(['constructor', '__proto__', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', 'caller', 'callee', 'mainModule', 'binding', 'dlopen', '_load', '_linkedBinding', 'createRequire', 'require', 'getBuiltinModule', 'eval', 'Function',
  // snapshots write files
  'toMatchSnapshot', 'toMatchInlineSnapshot', 'toMatchFileSnapshot', 'toThrowErrorMatchingSnapshot', 'toThrowErrorMatchingInlineSnapshot',
  // reflection: ways to read or change what a name hides, on any object (also through an alias of Object)
  'getOwnPropertyDescriptor', 'getOwnPropertyDescriptors', 'getOwnPropertyNames', 'getOwnPropertySymbols', 'getPrototypeOf', 'setPrototypeOf', 'defineProperty', 'defineProperties', 'fromCharCode', 'fromCodePoint']);
/** A skipped, focused, conditional or unrepeatable test, as a member or an option. */
const SKIP_PROP: ReadonlySet<string> = new Set(['skip', 'only', 'todo', 'skipIf', 'runIf', 'fails', 'each', 'for', 'fixme', 'retry', 'repeats']);
const SKIP_IDENT: ReadonlySet<string> = new Set(['xit', 'xtest', 'xdescribe', 'fit', 'ftest', 'fdescribe']);
const BANNED_STRING: ReadonlySet<string> = new Set(['constructor', '__proto__', 'eval', 'Function', 'binding', 'dlopen', 'mainModule', 'createRequire', 'getBuiltinModule', 'child_process']);
const DANGEROUS_MODULES = /^(?:node:)?(?:child_process|vm|worker_threads|cluster|dgram|net|tls|http2|https|module|process|inspector|repl|v8|fs|fs\/promises|os|dns|readline|zlib|crypto|stream|events)$/;
/** The globals a test may use as an object, and the members it may take from each (`*`: any). Anything else on them is refused. */
const GLOBAL_MEMBERS: Readonly<Record<string, ReadonlySet<string>>> = {
  JSON: new Set(['parse', 'stringify']),
  Math: new Set(['*']),
  Number: new Set(['isInteger', 'isFinite', 'isNaN', 'isSafeInteger', 'parseFloat', 'parseInt', 'MAX_SAFE_INTEGER', 'MIN_SAFE_INTEGER', 'EPSILON', 'MAX_VALUE', 'MIN_VALUE', 'POSITIVE_INFINITY', 'NEGATIVE_INFINITY', 'NaN']),
  String: new Set(['raw']),
  Boolean: new Set([]),
  Array: new Set(['isArray', 'from', 'of']),
  Object: new Set(['keys', 'values', 'entries', 'assign', 'freeze', 'fromEntries', 'is', 'hasOwn']),
  Promise: new Set(['resolve', 'reject', 'all', 'allSettled', 'race', 'any', 'withResolvers']),
  Date: new Set(['now', 'UTC', 'parse']),
  URL: new Set([]),
};
/** Other free names a test may use (constructors, timers, console). A free name that is not declared in the file and not here (or above) is refused. */
const ALLOWED_GLOBALS: ReadonlySet<string> = new Set(['undefined', 'NaN', 'Infinity', 'arguments', 'console', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'setImmediate', 'clearImmediate', 'queueMicrotask', 'structuredClone', 'Buffer', 'URLSearchParams', 'TextEncoder', 'TextDecoder',
  'AbortController', 'AbortSignal', 'Headers', 'Request', 'Response', 'FormData', 'Blob', 'Map', 'Set', 'WeakMap', 'WeakSet', 'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError', 'AggregateError', 'parseInt', 'parseFloat', 'isNaN', 'isFinite',
  'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI', 'BigInt', 'Uint8Array', 'Uint16Array', 'Uint32Array', 'Int8Array', 'Int16Array', 'Int32Array', 'Float32Array', 'Float64Array', 'ArrayBuffer', 'DataView', 'performance', '__dirname', '__filename']);
/** node:http: the members a test may take, and the two that open a connection (their target must be a literal local address). */
const HTTP_OK: ReadonlySet<string> = new Set(['createServer', 'request', 'get']);
const HTTP_NAMES: ReadonlySet<string> = HTTP_OK;
const HTTP_CALLS: ReadonlySet<string> = new Set(['request', 'get']);
const HTTP_OPTION_KEYS: ReadonlySet<string> = new Set(['method', 'path', 'port', 'headers', 'host', 'hostname', 'timeout']);
const LOCAL_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '::1']);
/** The hostnames (as the WHATWG URL parser reports them) an http request URL may have. */
const LOCAL_URL_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '[::1]']);
const URL_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]', 'example.com']);
/**
 * Names a file may not DECLARE (variable, function, class, parameter, catch, destructuring, import of another module): the listed globals, the banned names,
 * the vitest and node:test API names, process, vi, require, and anything starting with `__`. So no inner scope can shadow what the checks rely on, and
 * the flat set of declared names is enough (no scope analysis). The API names may only be bound by importing them from their own module, once.
 */
const RESERVED: ReadonlySet<string> = new Set([...Object.keys(GLOBAL_MEMBERS), ...ALLOWED_GLOBALS, ...BANNED_IDENT, ...BANNED_PROP, ...VITEST_NAMES, ...NODE_TEST_NAMES, 'process', 'vi', 'require', 'exports', 'module']);
const API_MODULES: ReadonlySet<string> = new Set(['vitest', 'node:test', 'node:assert', 'node:assert/strict', 'node:http']);
const TS_NAMESPACE_RE = /(?:^|[;{}/])\s*(?:export\s+)?(?:declare\s+)?(?:namespace|module)\s+[A-Za-z_$"']/m;
const TS_ENUM_RE = /(?:^|[;{}/])\s*(?:export\s+)?(?:declare\s+)?(?:const\s+)?enum\s+[A-Za-z_$]/m;
const RELATIVE_RE = /^\.{1,2}(?:\/[A-Za-z0-9_@.+~-]+)*\/?$/;
const BARE_RE = /^(?:@[a-z0-9][a-z0-9._-]{0,213}\/)?[a-z0-9][a-z0-9._-]{0,213}(?:\/[A-Za-z0-9_@+-][A-Za-z0-9_@.+-]*)*$/;
const ALLOW_TEXT = "vitest, node:assert, node:assert/strict, node:test, node:path, node:url, node:util, node:http, a relative path inside the service, or a package in the service's dependencies";

// ---------- the tree ----------

// A parsed node: acorn's ESTree shapes, read by field name. Every field is checked where it is read.
interface N { type: string; start: number; loc?: { start: { line: number } }; [k: string]: any }   // eslint-disable-line @typescript-eslint/no-explicit-any
const isNode = (v: unknown): v is N => typeof v === 'object' && v !== null && typeof (v as { type?: unknown }).type === 'string';
const NOT_CHILD: ReadonlySet<string> = new Set(['type', 'start', 'end', 'loc', 'range']);
class TooDeep extends Error {}

function kids(n: N): N[] {
  const out: N[] = [];
  for (const k of Object.keys(n)) {
    if (NOT_CHILD.has(k)) continue;
    const v: unknown = n[k];
    if (Array.isArray(v)) { for (const x of v) if (isNode(x)) out.push(x); } else if (isNode(v)) out.push(v);
  }
  return out;
}
function walk(n: N, anc: N[], visit: (n: N, anc: readonly N[]) => void, depth = 0): void {
  if (depth > MAX_DEPTH) throw new TooDeep();
  visit(n, anc);
  anc.push(n);
  for (const c of kids(n)) walk(c, anc, visit, depth + 1);
  anc.pop();
}

/** The value of a key or specifier expression that can be read without running code: strings, numbers, `+` of them, `-`/`*` of numbers. */
function fold(n: N): string | number | undefined {
  switch (n.type) {
    case 'Literal': return typeof n.value === 'string' || typeof n.value === 'number' ? n.value : undefined;
    case 'TemplateLiteral': return n.expressions.length === 0 && typeof n.quasis[0]?.value?.cooked === 'string' ? n.quasis[0].value.cooked as string : undefined;
    case 'UnaryExpression': {
      const v = isNode(n.argument) ? fold(n.argument) : undefined;
      return typeof v === 'number' ? (n.operator === '-' ? -v : n.operator === '+' ? v : undefined) : undefined;
    }
    case 'BinaryExpression': {
      const a = isNode(n.left) ? fold(n.left) : undefined;
      const b = isNode(n.right) ? fold(n.right) : undefined;
      if (a === undefined || b === undefined) return undefined;
      if (n.operator === '+') return typeof a === 'number' && typeof b === 'number' ? a + b : `${a}${b}`;
      if (typeof a === 'number' && typeof b === 'number') return n.operator === '-' ? a - b : n.operator === '*' ? a * b : undefined;
      return undefined;
    }
    default: return undefined;
  }
}
/** A string written out in one piece: a string literal or a template without `${}`. Module specifiers must be this (a `+` of two literals is not). */
const literalString = (n: N | undefined): string | undefined => (n !== undefined && ((n.type === 'Literal' && typeof n.value === 'string') || (n.type === 'TemplateLiteral' && n.expressions.length === 0)) ? staticString(n) : undefined);
const staticString = (n: N | undefined): string | undefined => { const v = n === undefined ? undefined : fold(n); return typeof v === 'string' ? v : undefined; };
/** A template literal as text: its quasis joined with the value of each `${}` that folds to a string or number, and a sentinel for the rest. */
const templateText = (n: N): string => (n.quasis as N[]).map((q, i) => {
  const e: unknown = (n.expressions as unknown[])[i];
  const v = i < (n.expressions as unknown[]).length && isNode(e) ? fold(e) : undefined;
  return `${String(q.value?.cooked ?? '')}${i < (n.expressions as unknown[]).length ? (v === undefined ? '\uFFFF' : String(v)) : ''}`;
}).join('');
const isLiteralish = (n: N): boolean => n.type === 'Literal' || (n.type === 'TemplateLiteral' && n.expressions.length === 0) || (n.type === 'UnaryExpression' && isNode(n.argument) && isLiteralish(n.argument));
const isFn = (n: unknown): n is N => isNode(n) && (n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression');
const ident = (n: unknown, name?: string): boolean => isNode(n) && n.type === 'Identifier' && (name === undefined || n.name === name);

// ---------- the analysis of one file ----------

export interface TestFileReport {
  /** Why the file is refused (empty: it passes). Plain sentences; every piece of the file's own text in them goes through the active vault. */
  problems: string[];
  tests: number;
  /** Assertions written directly in a test body. */
  assertions: number;
  /** False when the file could not be read as code (the counts are 0). */
  parsed: boolean;
}

const show = (s: string, max = 60): string => activeSafeText(s, max);

/**
 * Judges one file of a service. `rel` is the path inside the service (its folder resolves the relative imports; its name says whether tests are required),
 * `deps` the service's own `dependencies` names. Never throws for any content.
 */
export function analyzeTestFile(rel: string, content: string, deps: readonly string[], moduleType: 'module' | 'commonjs' = 'commonjs'): TestFileReport {
  const fail = (why: string): TestFileReport => ({ problems: [why], tests: 0, assertions: 0, parsed: false });
  if (typeof content !== 'string') return fail('the file is not text');
  if (Buffer.byteLength(content, 'utf8') > MAX_TEST_FILE_BYTES) return fail(`the file is over ${MAX_TEST_FILE_BYTES / 1024} KB`);
  if (content.includes('\0')) return fail('the file holds a NUL byte');
  const ext = rel.slice(rel.lastIndexOf('.') + 1);
  let code = content;
  if (ext === 'ts') {
    if (TS_NAMESPACE_RE.test(content)) return fail('the file has a TypeScript namespace or module block, which pipegen can not check (write plain functions)');
    if (TS_ENUM_RE.test(content)) return fail('the file has a TypeScript enum, which compiles to computed code pipegen can not check (use a plain object)');
    try { code = transform(content, { transforms: ['typescript'], disableESTransforms: true, keepUnusedImports: true, filePath: rel }).code; } catch { return fail('the file can not be read as TypeScript'); }
  }
  // Strict and sloppy parsing differ (`<!--` is a comment in a script and an operator in a module), and the runner may take a file either way. So:
  // .cjs is a script, .mjs and .ts are modules, and a .js follows the service's package.json "type" ("module": a module; otherwise BOTH readings must
  // be checked, and the problems of each are reported).
  const modes: boolean[] = ext === 'cjs' ? [true] : ext === 'js' && moduleType === 'commonjs' ? [true, false] : [false];
  const reports: TestFileReport[] = [];
  let parseError = '';
  for (const script of modes) {
    let program: N;
    try {
      program = parse(code, { ecmaVersion: 'latest', sourceType: script ? 'script' : 'module', locations: true, allowHashBang: true }) as unknown as N;
    } catch (e) {
      const line = typeof e === 'object' && e !== null && 'loc' in e && typeof (e as { loc?: { line?: unknown } }).loc?.line === 'number' ? ` near line ${(e as { loc: { line: number } }).loc.line}` : '';
      parseError = `the file does not parse as ${ext === 'ts' ? 'TypeScript' : 'JavaScript'}${line}`;
      continue;
    }
    reports.push(analyzeProgram(rel, program, script, deps));
  }
  if (reports.length === 0) return fail(parseError);
  const first = reports[0] as TestFileReport;
  if (reports.some((r) => !r.parsed)) return reports.find((r) => !r.parsed) as TestFileReport;
  return { problems: [...new Set(reports.flatMap((r) => r.problems))], tests: Math.min(...reports.map((r) => r.tests)), assertions: Math.min(...reports.map((r) => r.assertions)), parsed: first.parsed };
}

function analyzeProgram(rel: string, program: N, script: boolean, deps: readonly string[]): TestFileReport {
  const problems = new Set<string>();
  const fail = (why: string): TestFileReport => ({ problems: [why], tests: 0, assertions: 0, parsed: false });
  const depSet = new Set(deps.filter((d) => NPM_NAME_RE.test(d) && !isBuiltin(d)));
  const dir = posix.dirname(rel);
  const add = (n: N | undefined, why: string): void => { if (problems.size < MAX_PROBLEMS) problems.add(`${n?.loc === undefined ? '' : `line ${n.loc.start.line}: `}${why}`); };

  // the names bound to node:assert, so a call on them counts as an assertion (top-level imports and requires)
  const assertNames = new Set<string>();
  for (const s of program.body as N[]) {
    if (s.type === 'ImportDeclaration' && ASSERT_MODULES.has(String(s.source?.value))) for (const sp of s.specifiers as N[]) { if (ident(sp.local)) assertNames.add(sp.local.name); }
    if (s.type === 'VariableDeclaration') {
      for (const d of s.declarations as N[]) {
        const init = d.init;
        if (!isNode(init) || init.type !== 'CallExpression' || !ident(init.callee, 'require') || !ASSERT_MODULES.has(literalString(init.arguments?.[0]) ?? '')) continue;
        if (ident(d.id)) assertNames.add(d.id.name);
        else if (isNode(d.id) && d.id.type === 'ObjectPattern') for (const p of d.id.properties as N[]) { if (p.type === 'Property' && ident(p.value)) assertNames.add(p.value.name); }
      }
    }
  }

  // every name the file declares, with how often. Reserved names can not be declared (see RESERVED), so a free listed global is always the real one.
  const declared = new Set<string>();
  const declCount = new Map<string, number>();
  const apiLocals = new Set<string>();
  const importLocals = new Set<string>();
  const isTestFile = isTestName(posix.basename(rel));
  /** `exempt`: the name is an API name imported from its own module under its own name, so it may be a reserved name. `track`: the name is bound to an API module (declaring it again is refused). */
  const declare = (t: unknown, site: N, exempt = false, track = false): void => {
    if (!isNode(t)) return;
    if (t.type === 'Identifier') {
      const name = t.name as string;
      declared.add(name);
      declCount.set(name, (declCount.get(name) ?? 0) + 1);
      if (track) apiLocals.add(name);
      if (!exempt && (RESERVED.has(name) || name.startsWith('__'))) add(site, `it declares ${show(name)}, a name pipegen reserves (a listed global, an API name, or one starting with __), which could hide what the checks rely on`);
    }
    else if (t.type === 'ObjectPattern') { for (const q of t.properties as N[]) declare(q.type === 'Property' ? q.value : q.argument, site, exempt, track); }
    else if (t.type === 'ArrayPattern') { for (const q of t.elements as unknown[]) declare(q, site, exempt, track); }
    else if (t.type === 'AssignmentPattern') declare(t.left, site, exempt, track);
    else if (t.type === 'RestElement') declare(t.argument, site, exempt, track);
  };
  /** The names a module of the API set offers as its own (the exemption is keyed on module and name together). */
  const ownNames = (src: string): ReadonlySet<string> | null => (src === 'vitest' ? VITEST_NAMES : src === 'node:test' ? NODE_TEST_NAMES : null);
  // the names bound to node:http, whole (`http.get`) or by name (`get`), so a connection's target can be checked
  const httpNames = new Set<string>();
  const httpNamed = new Map<string, string>();
  try {
    walk(program, [], (n, anc) => {
      if (n.type === 'VariableDeclarator') {
        const init = n.init;
        const top = anc[anc.length - 1]?.type === 'VariableDeclaration' && anc[anc.length - 2]?.type === 'Program';
        const mod = top && isNode(init) && init.type === 'CallExpression' && ident(init.callee, 'require') ? literalString(init.arguments?.[0]) ?? '' : '';
        const track = API_MODULES.has(mod);
        const own = ownNames(mod);
        if (own !== null && isNode(n.id) && n.id.type === 'ObjectPattern') {
          for (const q of n.id.properties as N[]) declare(q.type === 'Property' ? q.value : q.argument, n, q.type === 'Property' && ident(q.key) && !q.computed && ident(q.value) && q.key.name === q.value.name && own.has(q.key.name), true);
        } else declare(n.id, n, false, track);
      }
      else if (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression') { declare(n.id, n); for (const q of n.params as unknown[]) declare(q, n); }
      else if (n.type === 'ClassDeclaration' || n.type === 'ClassExpression') declare(n.id, n);
      else if (n.type === 'CatchClause') declare(n.param, n);
      else if (n.type === 'ImportDeclaration') {
        const src = String(n.source?.value);
        for (const sp of n.specifiers as N[]) {
          const own = ownNames(src);
          const imported = sp.type === 'ImportSpecifier' ? String(sp.imported?.name ?? sp.imported?.value) : '';
          if (ident(sp.local)) importLocals.add(sp.local.name);
          declare(sp.local, n, own !== null && sp.type === 'ImportSpecifier' && own.has(imported) && ident(sp.local, imported), API_MODULES.has(src));
          if (src !== 'node:http' || !ident(sp.local)) continue;
          if (sp.type === 'ImportSpecifier') httpNamed.set(sp.local.name, String(sp.imported?.name ?? sp.imported?.value)); else httpNames.add(sp.local.name);
        }
      }
    });
  } catch { return fail('the file is nested too deeply to check'); }
  for (const name of apiLocals) if ((declCount.get(name) ?? 0) > 1) add(undefined, `${show(name)} is bound to an API module (vitest, node:test, node:assert or node:http) and is declared again, which could shadow it`);
  for (const s of program.body as N[]) {
    if (s.type !== 'VariableDeclaration') continue;
    for (const d of s.declarations as N[]) {
      const init = d.init;
      if (!isNode(init) || init.type !== 'CallExpression' || !ident(init.callee, 'require') || literalString(init.arguments?.[0]) !== 'node:http') continue;
      if (ident(d.id)) httpNames.add(d.id.name);
      else if (isNode(d.id) && d.id.type === 'ObjectPattern') for (const q of d.id.properties as N[]) { if (q.type === 'Property' && ident(q.value) && ident(q.key)) httpNamed.set(q.value.name, q.key.name); }
    }
  }
  /** Why `this` is refused here, or null. Outside strict code `this` in a plain function is the global object; class bodies are always strict. */
  const thisProblem = (anc: readonly N[], isScript: boolean): string | null => {
    for (let i = anc.length - 1; i >= 0; i--) {
      const a = anc[i] as N;
      if (a.type === 'ArrowFunctionExpression') continue;
      if (a.type === 'PropertyDefinition' || a.type === 'StaticBlock' || a.type === 'ClassBody') return null;
      if (a.type === 'FunctionDeclaration' || a.type === 'FunctionExpression') {
        const owner = anc[i - 1];
        return owner?.type === 'MethodDefinition' ? null : 'this inside a plain function is refused (outside strict mode it is the global object); use an arrow function or a class method';
      }
    }
    return isScript ? 'this at the top of a script is the global object, so it is refused' : null;
  };
  /** Whether text starts with a literal http(s) URL whose scheme, host and port are written out and the host is local (parsed with the WHATWG URL parser). */
  const isLocalHttpUrl = (text: string): boolean => {
    const m = /^(https?):\/\/([^/?#]*)/.exec(text);
    if (m === null || m[0].includes('￿') || /[\s\\@'"`<>]/.test(m[0])) return false;
    try { const u = new URL(m[0]); return LOCAL_URL_HOSTS.has(u.hostname) && u.username === '' && u.password === ''; } catch { return false; }
  };
  /** An options object whose keys are plain and whose host (if any) is a literal local address. */
  const httpOptionsOk = (o: N): boolean => (o.properties as N[]).every((q) => {
    if (q.type !== 'Property' || q.computed) return false;
    const key = ident(q.key) ? q.key.name : isNode(q.key) && q.key.type === 'Literal' ? String(q.key.value) : '';
    if (!HTTP_OPTION_KEYS.has(key)) return false;
    return (key !== 'host' && key !== 'hostname') || LOCAL_HOSTS.has(literalString(q.value) ?? '');
  });
  /** Why a call of node:http request/get is refused: its target must be a literal local address, and nothing but a callback (or options, with a URL) may follow. */
  const httpCallProblem = (call: N): string | null => {
    const args = call.arguments as N[];
    const a0 = args[0];
    const why = 'an http request must name its target as a literal local address: a string starting with http://127.0.0.1, http://localhost or http://[::1] (host and port written out), or an options object whose host is such a literal or absent; only a callback may follow';
    if (a0 === undefined) return why;
    const lit = literalString(a0);
    const isUrl = lit !== undefined || a0.type === 'TemplateLiteral';
    let rest = args.slice(1);
    if (isUrl) {
      if (!isLocalHttpUrl(lit ?? templateText(a0))) return why;
      if (rest[0]?.type === 'ObjectExpression') { if (!httpOptionsOk(rest[0])) return why; rest = rest.slice(1); }
    } else if (a0.type === 'ObjectExpression') { if (!httpOptionsOk(a0)) return why; } else return why;
    if (rest.length > 1 || (rest.length === 1 && !isFn(rest[0]))) return why;
    return null;
  };

  /** Why a module specifier is refused, or null. */
  const specProblem = (spec: string): string | null => {
    if (ALLOWED_BUILTINS.has(spec)) return null;
    if (/^\.\.?(?:\/|$)/.test(spec)) {
      if (!RELATIVE_RE.test(spec)) return `imports ${JSON.stringify(show(spec))}, a relative path with characters pipegen does not accept`;
      const resolved = posix.normalize(posix.join(dir, spec));
      if (resolved === '..' || resolved.startsWith('../')) return `imports ${JSON.stringify(show(spec))}, which leaves the service folder`;
      if (resolved.split('/').some((s) => s === 'node_modules' || (s.startsWith('.') && s !== '.'))) return `imports ${JSON.stringify(show(spec))}, a path through a hidden or vendored folder`;
      return null;
    }
    if (DANGEROUS_MODULES.test(spec)) return `imports ${JSON.stringify(show(spec))}, which can run commands, open sockets, read or delete files or load code outside the test`;
    if (BARE_RE.test(spec) && !spec.split('/').includes('..') && !spec.split('/').includes('.')) {
      const parts = spec.split('/');
      const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : (parts[0] as string);
      if (depSet.has(name)) return null;
    }
    return `imports ${JSON.stringify(show(spec))}, which is not on the allowlist (${ALLOW_TEXT})`;
  };
  const checkSource = (n: N, source: unknown, relativeOnly: boolean): void => {
    const spec = isNode(source) ? literalString(source) : undefined;
    if (spec === undefined) { add(n, 'a module specifier that is not a plain string can not be checked'); return; }
    const p = specProblem(spec);
    if (p !== null) add(n, p);
    else if (relativeOnly && !/^\.\.?(?:\/|$)/.test(spec)) add(n, `re-exports ${JSON.stringify(show(spec))}; only relative files may be re-exported`);
  };
  const checkSpecifiers = (n: N, spec: string): void => {
    const names = spec === 'vitest' ? VITEST_NAMES : spec === 'node:test' ? NODE_TEST_NAMES : spec === 'node:http' ? HTTP_NAMES : null;
    if (names === null) return;
    for (const sp of n.specifiers as N[]) {
      if (spec === 'node:http' && sp.type !== 'ImportSpecifier') continue;   // the whole module is fine: its members are checked where they are used
      const imported = sp.type === 'ImportSpecifier' ? (isNode(sp.imported) ? (sp.imported.name ?? sp.imported.value) : undefined) : undefined;
      if (typeof imported !== 'string' || !names.has(imported)) { add(n, `imports from ${JSON.stringify(spec)} only ${[...names].join(', ')}, written as named imports`); return; }
      if (!ident(sp.local, imported)) { add(n, `imports ${imported} from ${JSON.stringify(spec)} under another name; pipegen needs the plain name`); return; }
    }
  };

  /** Whether a statement of a test body is an assertion that counts: `expect(x).matcher(...)` or an assert call, not on a bare literal. */
  const isAssertionStatement = (s: N): boolean => {
    let e: unknown = s.type === 'ExpressionStatement' ? s.expression : s.type === 'ReturnStatement' ? s.argument : undefined;
    while (isNode(e) && e.type === 'AwaitExpression') e = e.argument;
    if (!isNode(e) || e.type !== 'CallExpression') return false;
    const c: N = e.callee;
    if (isNode(c) && c.type === 'MemberExpression') {
      let o: N = c.object;
      while (isNode(o) && o.type === 'MemberExpression') o = o.object;
      if (isNode(o) && o.type === 'CallExpression') {
        const oc: N = o.callee;
        const isExpect = ident(oc, 'expect') || (isNode(oc) && oc.type === 'MemberExpression' && !oc.computed && ident(oc.object, 'expect') && ident(oc.property) && (oc.property.name === 'soft' || oc.property.name === 'poll'));
        if (isExpect) return o.arguments.length >= 1 && isNode(o.arguments[0]) && !isLiteralish(o.arguments[0]);
      }
      let root: N = c;
      while (isNode(root) && root.type === 'MemberExpression') root = root.object;
      if (ident(root) && assertNames.has(root.name)) return !(c.computed !== true && ident(c.property, 'fail')) && (e.arguments as N[]).some((a) => isNode(a) && !isLiteralish(a));
      return false;
    }
    return ident(c) && assertNames.has(c.name) && (e.arguments as N[]).some((a) => isNode(a) && !isLiteralish(a));
  };
  const isDescribeCall = (n: unknown): boolean => isNode(n) && n.type === 'CallExpression' && (ident(n.callee, 'describe')
    || (isNode(n.callee) && n.callee.type === 'MemberExpression' && !n.callee.computed && ident(n.callee.object, 'describe') && ident(n.callee.property, 'concurrent')));
  /** A test call must stand alone as a statement: at the top of the file, or directly in a describe body (never in a loop, condition or function). */
  const placedOk = (anc: readonly N[]): boolean => {
    let k = anc.length - 1;
    if (anc[k]?.type !== 'ExpressionStatement') return false;
    for (;;) {
      const p = anc[k - 1];
      if (p === undefined) return false;
      if (p.type === 'Program') return true;
      const fn = anc[k - 2], call = anc[k - 3], stmt = anc[k - 4];
      if (p.type === 'BlockStatement' && isFn(fn) && fn.body === p && isDescribeCall(call) && (call as N).arguments.includes(fn) && stmt?.type === 'ExpressionStatement') { k -= 4; continue; }
      return false;
    }
  };

  let tests = 0;
  let assertions = 0;
  const testCall = (n: N, anc: readonly N[]): void => {
    tests++;
    if (!placedOk(anc)) add(n, 'a test must be written on its own in the file or directly inside describe, never in a loop, a condition or another function');
    const [title, body, extra] = n.arguments as (N | undefined)[];
    const name = staticString(title);
    if (name === undefined || name.trim() === '') add(n, 'a test needs a plain string as its name');
    if (!isFn(body) || (n.arguments as unknown[]).length > 3 || (extra !== undefined && !(isNode(extra) && extra.type === 'Literal' && typeof extra.value === 'number'))) {
      add(n, "a test is written as it('name', () => { ... }), with the body in place and at most a number as the timeout");
      return;
    }
    const stmts: N[] = body.body.type === 'BlockStatement' ? body.body.body as N[] : [{ type: 'ExpressionStatement', start: body.start, expression: body.body }];
    const direct = stmts.filter(isAssertionStatement).length;
    assertions += direct;
    if (direct === 0) add(n, `the test ${JSON.stringify(show(name ?? ''))} has no assertion written directly in its body (an expect(value).matcher(...) or an assert call on a real value)`);
  };

  const urlProblem = (text: string): string | null => {
    if (/^(?:https?|wss?|ftp):\/{0,2}$/i.test(text)) return 'a bare URL scheme can not be checked';
    const found: string[] = [];
    const re = /([A-Za-z￿][A-Za-z0-9+.￿-]*):\/\/([^\s'"`<>]*)/g;
    for (let m = re.exec(text); m !== null; m = re.exec(text)) found.push(`${m[1]}://${m[2]}`);
    const rel2 = /^\/\/([^\s'"`<>]+)/.exec(text);
    if (rel2 !== null) found.push(`http://${rel2[1]}`);
    for (const u of found) {
      const authority = /^[^:]*:\/\/[^/?#]*/.exec(u)?.[0] ?? u;
      if (authority.includes('￿')) return 'a URL whose scheme, host or port is built at run time can not be checked (write them out; to use a server port, pass it in an http options object)';
      if (/[\\@]/.test(authority)) return 'a URL with a user name or a backslash before its path is refused';
      let url: URL;
      try { url = new URL(u.replaceAll('￿', 'x')); } catch { return `a URL pipegen can not read (${show(u, 40)})`; }
      if (url.username !== '' || url.password !== '') return 'a URL with a user name in it is refused';
      if (!URL_HOSTS.has(url.hostname)) return `the URL host ${JSON.stringify(show(url.hostname, 40))} is not localhost, 127.0.0.1, [::1] or example.com`;
    }
    return null;
  };

  const visit = (n: N, anc: readonly N[]): void => {
    const parent = anc[anc.length - 1];
    switch (n.type) {
      case 'ImportDeclaration': {
        if (Array.isArray(n.attributes) && n.attributes.length > 0) add(n, 'import attributes are not accepted');
        checkSource(n, n.source, false);
        const spec = literalString(n.source);
        if (spec !== undefined) checkSpecifiers(n, spec);
        return;
      }
      case 'ExportAllDeclaration':
      case 'ExportNamedDeclaration':
      case 'ExportDefaultDeclaration': {
        // a test file exports nothing; a helper may export its own bindings, never an import (a re-export would carry node:http or a package out of the checks)
        if (isTestFile) { add(n, 'a test file may not export anything'); return; }
        if (isNode(n.source)) { add(n, 'a helper may not re-export from another module (export ... from)'); return; }
        for (const sp of (n.specifiers ?? []) as N[]) { if (ident(sp.local) && importLocals.has(sp.local.name)) add(n, `a helper may not export ${show(sp.local.name)}, which comes from an import`); }
        if (n.type === 'ExportDefaultDeclaration' && ident(n.declaration) && importLocals.has(n.declaration.name)) add(n, `a helper may not export ${show(n.declaration.name)}, which comes from an import`);
        return;
      }
      case 'ImportExpression':
        if (isNode(n.options)) add(n, 'import() with options is not accepted');
        if (literalString(n.source) === 'node:http') add(n, 'node:http can only be imported at the top of the file, never with import()');
        checkSource(n, n.source, false);
        return;
      case 'ThisExpression': { const w = thisProblem(anc, script); if (w !== null) add(n, w); return; }
      case 'BinaryExpression': {
        // a URL built by joining pieces is read whole before the host check (the pieces of 'ht' + 'tp://x' are not URLs, the sum is)
        if (n.operator !== '+' || (parent?.type === 'BinaryExpression' && parent.operator === '+')) return;
        const parts: string[] = [];
        const flat = (x: N): void => {
          if (x.type === 'BinaryExpression' && x.operator === '+') { flat(x.left); flat(x.right); return; }
          const f = fold(x);
          parts.push(typeof f === 'string' ? f : typeof f === 'number' ? String(f) : x.type === 'TemplateLiteral' ? templateText(x) : '\uFFFF');
        };
        flat(n);
        const u = urlProblem(parts.join(''));
        if (u !== null) add(n, u);
        return;
      }
      case 'WithStatement': add(n, 'a with statement is not accepted'); return;
      case 'CallExpression': {
        const c: N = n.callee;
        if (isNode(c) && c.type === 'MemberExpression' && ident(c.object, 'vi') && (c.computed ? fold(c.property) === 'mock' : ident(c.property, 'mock'))) {
          const m = literalString(n.arguments[0]);
          if (m === undefined || !/^\.\.?\//.test(m)) add(n, 'vi.mock may name only a relative path inside the service, written as one string');
          else { const w = specProblem(m); if (w !== null) add(n, w); }
        }
        if (ident(c, 'require')) {
          const topLevel = parent?.type === 'VariableDeclarator' && parent.init === n && anc[anc.length - 2]?.type === 'VariableDeclaration' && anc[anc.length - 3]?.type === 'Program';
          if (!topLevel) add(n, "require() is accepted only at the top of the file, as const x = require('...')");
          if ((n.arguments as unknown[]).length !== 1) add(n, 'require() takes one plain string');
          else checkSource(n, n.arguments[0], false);
        } else if (ident(c, 'it') || ident(c, 'test') || (isNode(c) && c.type === 'MemberExpression' && !c.computed && (ident(c.object, 'it') || ident(c.object, 'test')) && ident(c.property, 'concurrent'))) {
          testCall(n, anc);
        } else if (isNode(c) && c.type === 'MemberExpression' && !c.computed && (ident(c.object, 'it') || ident(c.object, 'test')) && ident(c.property) && !SKIP_PROP.has(c.property.name)) {
          add(n, `${c.object.name}.${c.property.name} is a test form pipegen can not count`);
        }
        return;
      }
      case 'Identifier': {
        if (parent !== undefined) {
          const t = parent.type;
          if (t === 'MemberExpression' && parent.property === n && !parent.computed) return;
          if ((t === 'Property' || t === 'MethodDefinition' || t === 'PropertyDefinition') && parent.key === n && !parent.computed) return;
          if (t === 'MetaProperty' || t === 'LabeledStatement' || t === 'BreakStatement' || t === 'ContinueStatement' || t === 'ImportSpecifier' || t === 'ImportDefaultSpecifier' || t === 'ImportNamespaceSpecifier' || t === 'ExportSpecifier') return;
        }
        const name = n.name as string;
        if (BANNED_IDENT.has(name)) add(n, `${name} can run code or reach what the checks cover, so it is refused`);
        else if (SKIP_IDENT.has(name)) add(n, `${name} skips or focuses tests, which pipegen does not accept`);
        else if (name === 'require') { if (!(parent?.type === 'CallExpression' && parent.callee === n)) add(n, 'require can only be called with a plain string, never passed around'); }
        else if (httpNames.has(name) || httpNamed.has(name)) {
          const declSite = (parent?.type === 'VariableDeclarator' && parent.id === n) || (parent?.type === 'Property' && anc[anc.length - 2]?.type === 'ObjectPattern' && parent.value === n) || ((parent?.type === 'FunctionDeclaration' || parent?.type === 'FunctionExpression' || parent?.type === 'ArrowFunctionExpression') && (parent.id === n || (parent.params as unknown[]).includes(n))) || (parent?.type === 'CatchClause' && parent.param === n) || ((parent?.type === 'ClassDeclaration' || parent?.type === 'ClassExpression') && parent.id === n) || (parent?.type === 'AssignmentPattern' && parent.left === n) || parent?.type === 'RestElement' || parent?.type === 'ArrayPattern';
          if (httpNames.has(name)) {
            const call = anc[anc.length - 2];
            const asObject = parent?.type === 'MemberExpression' && parent.object === n && !parent.computed && call?.type === 'CallExpression' && call.callee === parent;
            if (!asObject && !declSite) add(n, 'the node:http module can only be used as http.get(...), http.request(...) or http.createServer(...), never as a value');
          } else if (!(parent?.type === 'CallExpression' && parent.callee === n) && !declSite) add(n, 'a function taken from node:http can only be called directly, never used as a value');
          else if (parent?.type === 'CallExpression' && parent.callee === n && HTTP_CALLS.has(httpNamed.get(name) as string)) { const w = httpCallProblem(parent); if (w !== null) add(n, w); }
        }
        else if (name === 'process') { if (!(parent?.type === 'MemberExpression' && parent.object === n)) add(n, 'process can only be used as process.env, process.cwd(), process.platform, process.nextTick, process.hrtime or process.uptime'); }
        else if (name === 'vi') { if (!(parent?.type === 'MemberExpression' && parent.object === n)) add(n, 'vi can only be used as vi.<helper>(...)'); }
        else if (GLOBAL_MEMBERS[name] !== undefined) {
          const asValue = parent?.type === 'MemberExpression' && parent.object === n;
          const asCallee = (parent?.type === 'CallExpression' || parent?.type === 'NewExpression') && parent.callee === n;
          const asArg = parent?.type === 'CallExpression' && parent.callee !== n;
          const asInstanceof = parent?.type === 'BinaryExpression' && parent.operator === 'instanceof' && parent.right === n;
          if (!(asValue || asCallee || asArg || asInstanceof)) add(n, `${name} can only be used as ${name}.<member>, called, or checked with instanceof`);
        } else if (!declared.has(name) && !ALLOWED_GLOBALS.has(name)) add(n, `${name} is a global pipegen does not list for tests, so it is refused`);
        return;
      }
      case 'MetaProperty': {
        if (n.meta?.name !== 'import') return;
        const k = parent?.type === 'MemberExpression' && parent.object === n ? (parent.computed ? fold(parent.property) : parent.property?.name) : undefined;
        if (typeof k !== 'string' || !META_OK.has(k)) add(n, 'import.meta can only be used as import.meta.url, .dirname or .filename');
        return;
      }
      case 'MemberExpression': {
        if (n.property?.type === 'PrivateIdentifier') return;
        let name: string;
        if (n.computed) {
          const k = isNode(n.property) ? fold(n.property) : undefined;
          if (k === undefined) { add(n, 'a computed property access whose key can not be read statically is not accepted (use a plain name, a literal, .at(), destructuring or a Map)'); return; }
          name = String(k);
        } else name = String(n.property?.name);
        if (SKIP_PROP.has(name)) add(n, `.${show(name)} skips, focuses or repeats tests, which pipegen does not accept`);
        else if (BANNED_PROP.has(name)) add(n, `.${show(name)} is refused (it reaches code execution, other modules or files outside the test)`);
        if (isNode(n.object) && n.object.type === 'Identifier') {
          const g = GLOBAL_MEMBERS[n.object.name as string];
          if (g !== undefined && !g.has('*') && !g.has(name)) add(n, `${n.object.name}.${show(name)} is not on the list of members tests may use (${[...g].join(', ') || 'none'})`);
          if (httpNames.has(n.object.name)) {
            if (!HTTP_OK.has(name)) add(n, `http.${show(name)} is refused (createServer, request, get, STATUS_CODES and METHODS are accepted)`);
            else if (HTTP_CALLS.has(name)) {
              const call = anc[anc.length - 1];
              if (call?.type === 'CallExpression' && call.callee === n) { const w = httpCallProblem(call); if (w !== null) add(n, w); } else add(n, `http.${name} can only be called`);
            }
          }
        }
        if (ident(n.object, 'process') && !PROCESS_OK.has(name)) add(n, `process.${show(name)} is refused`);
        if (ident(n.object, 'vi') && !VI_OK.has(name)) add(n, `vi.${show(name)} is refused (only fn, spyOn, the timer helpers and stubEnv are accepted)`);
        return;
      }
      case 'Property': {
        if (parent?.type !== 'ObjectPattern' && parent?.type !== 'ObjectExpression') return;
        let name: string | undefined;
        if (n.computed) { const k = isNode(n.key) ? fold(n.key) : undefined; name = k === undefined ? undefined : String(k); if (name === undefined && parent.type === 'ObjectPattern') add(n, 'a destructured key that can not be read statically is not accepted'); }
        else name = ident(n.key) ? n.key.name : isNode(n.key) && n.key.type === 'Literal' ? String(n.key.value) : undefined;
        if (name !== undefined && (SKIP_PROP.has(name) || BANNED_PROP.has(name))) add(n, `the name ${JSON.stringify(show(name))} is refused (skipping, focusing, retrying and code-reaching names)`);
        return;
      }
      case 'Literal':
        if (typeof n.value === 'string') {
          if (BANNED_STRING.has(n.value)) add(n, `the string ${JSON.stringify(show(n.value))} is refused`);
          const u = urlProblem(n.value);
          if (u !== null) add(n, u);
        }
        return;
      case 'TemplateLiteral': {
        const quasis = (n.quasis as N[]).map((q) => (typeof q.value?.cooked === 'string' ? q.value.cooked as string : ''));
        for (const q of quasis) if (BANNED_STRING.has(q)) add(n, `the string ${JSON.stringify(show(q))} is refused`);
        const u = urlProblem(templateText(n));
        if (u !== null) add(n, u);
        return;
      }
      default:
    }
  };

  try { walk(program, [], visit); } catch (e) {
    if (e instanceof TooDeep || e instanceof RangeError) return fail('the file is nested too deeply to check');
    throw e;
  }
  if (isTestName(posix.basename(rel)) && tests === 0) add(undefined, 'the file has no test (it(...) or test(...) written in the file or directly in describe)');
  return { problems: [...problems], tests, assertions, parsed: true };
}

/**
 * The problems of one created file at repo path `path`, for the judge and the guard: the path must be a starter-test path of a service in `roots`
 * (the deepest service that holds it), and the content must pass analyzeTestFile with that service's own dependency names (`depsOf`).
 */
export function starterTestFileProblems(path: string, content: string, o: { roots: readonly string[]; depsOf: (root: string) => readonly string[] | undefined; typeOf?: (root: string) => 'module' | 'commonjs' | undefined }): string[] {
  const owner = starterOwner(path, o.roots);
  if (owner === null) return [`${show(path, 80)} is not a path starter tests may use (${starterTestPathProblem(path) ?? 'it is not inside a service folder'})`];
  return analyzeTestFile(owner.rel, content, o.depsOf(owner.root) ?? [], o.typeOf?.(owner.root) ?? 'commonjs').problems;
}

/** The tests and the assertions of one file; null when it does not parse. */
export function fileStats(rel: string, content: string): { tests: number; assertions: number } | null {
  const r = analyzeTestFile(rel, content, []);
  return r.parsed ? { tests: r.tests, assertions: r.assertions } : null;
}
