// Which packages are not services of their own (P55, batch B, hand checks 2026-10-29). A folder with a `start` or `dev`
// script, but no server framework, no port and no Dockerfile of its own, is runnable only by that script's name. Three
// generic cases turn out not to be a standalone service, so the audit stops offering it an image, a Dockerfile, DAST or
// a deploy check:
//   - 'one-shot': every run script is `node <file>` and that file (and the repo files it imports, bounded) can be shown
//     to start nothing that keeps running: no listener, timer, event handler, child process, or package that isn't a
//     Node built-in without a network or process API. It runs, prints and exits.
//   - 'built-in-image': another folder's Dockerfile copies this folder into its image (a frontend built into the backend
//     image), so it is part of that service, not a service to build and scan twice.
//   - 'email-templates': a package of an email-template tool (react-email, mjml, maizzle) is a design-time tool that
//     exports files; nothing deploys it.
// Everything here is read through the caller's `read` (the read limits, no symbolic links), is bounded, and is
// conservative: anything that can't be shown leaves the folder runnable. P57 (I1): each case needs strong proof:
//   - one-shot: the files have no loop (while, do, for) and no function that may call itself, on top of the rest;
//   - built-in-image: the Dockerfile copies the whole folder, and it is the Dockerfile of another service's folder;
//   - email-templates: no port, no server dependency, and every run script is the email tool's own CLI.
import { builtinModules } from 'node:module';
import { posix } from 'node:path';
import { asString, baseOf, dirOf, inDir } from './manifest.js';
import { regexLines, regexSafe } from './limits.js';
import type { Obj } from './manifest.js';
import type { NotStandalone, Service } from '../types.js';

/** Files read to prove a script one-shot (the entry and what it imports), and the size of each. */
const MAX_ONE_SHOT_FILES = 12;
const MAX_ONE_SHOT_BYTES = 64 * 1024;
/** Dockerfiles read for COPY lines, and COPY sources kept. */
const MAX_DOCKERFILES = 20;
const MAX_COPY_SOURCES = 400;
/** The scripts that run a service (isRunnable and the type rules read the same list). */
export const RUN_SCRIPTS: readonly string[] = ['start', 'dev', 'serve'];

/** The email-template tools whose package is a design-time tool, by dependency name. */
const EMAIL_TOOLS = ['react-email', '@react-email/components', '@react-email/render', 'mjml', '@maizzle/framework', 'maizzle'];

/** Node built-ins that open a socket, start a process or a thread, or read the terminal: a script using one may keep running. */
const LONG_RUNNING_BUILTINS: ReadonlySet<string> = new Set(['http', 'https', 'http2', 'net', 'tls', 'dgram', 'cluster', 'worker_threads', 'child_process', 'readline', 'repl', 'inspector', 'tty', 'dns',
  // P57 (I1): timers/promises (scheduler.wait, setInterval as an async iterator) and events (on, once) can keep a script alive
  'timers', 'events']);
/** P57 (I1): a loop keyword: a script with one may keep running (a poller), so it is never shown one-shot. */
const LOOP_RE = /\b(?:while|do|for)\b/;
/** P57 (I1): a declared function's name, so a call of it inside the file (recursion is a loop too) can be found. */
const FUNCTION_NAME_RE = /\bfunction\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)|\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$]*\s*=>)/g;
/** P57 (I1): a call: a name right before `(` (one pass per line). */
const CALL_RE = /(?<![A-Za-z0-9_$.])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
/** P57 (I1): dependencies that make a package a server (it listens), whatever else it uses. */
export const SERVER_DEPS: readonly string[] = ['hono', '@hono/node-server', 'h3', 'elysia', 'express', 'fastify', 'koa', '@nestjs/core', 'next', 'nuxt', '@remix-run/node', '@remix-run/serve',
  '@sveltejs/kit', 'astro', 'nitropack', '@hapi/hapi', 'restify', 'polka', 'micro', 'srvx', 'socket.io', 'ws', 'graphql-yoga', '@apollo/server', 'apollo-server'];
/** P57 (I1): the email tools' own CLIs (react-email's `email`, mjml, maizzle), optionally through npx / bunx / pnpm exec. */
const EMAIL_CLI_RE = /^(?:(?:npx|bunx|pnpm exec|yarn)\s+)?(?:email|mjml|maizzle)(?:\s|$)/;
const BUILTINS: ReadonlySet<string> = new Set(builtinModules.map((m) => m.replace(/^node:/, '')));
/** Text that starts or keeps something running (a server, a timer, an event handler, a loop). Case-sensitive, linear. */
const LONG_RUNNING_RE = /\b(?:listen|createServer|serve|setInterval|setTimeout|setImmediate|WebSocket|addEventListener|process\.(?:stdin|on|once)|\.on\s*\(|fork|spawn|exec|execSync|cron|schedule|watch|Server|app\.use)\b|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/;

export interface DockerCopy { dockerDir: string; source: string }

/** The repo-relative COPY/ADD sources of one Dockerfile's text (not `--from=` copies), as the repo root or the Dockerfile's folder would hold them. */
export function copySources(dockerDir: string, text: string, has: (path: string) => boolean): string[] {
  const sources: string[] = [];
  const lines = regexLines(text).slice(0, 4000);
  for (let i = 0; i < lines.length && sources.length < MAX_COPY_SOURCES; i++) {
    let line = (lines[i] as string).trim();
    while (line.endsWith('\\') && i + 1 < lines.length) line = `${line.slice(0, -1)} ${(lines[++i] as string).trim()}`;
    const m = /^(?:COPY|ADD)\s+(.*)$/i.exec(line);
    if (!m || !regexSafe(line)) continue;
    const words = (m[1] as string).replace(/[[\],"]/g, ' ').split(/\s+/).filter((w) => w !== '');
    if (words.some((w) => w.toLowerCase().startsWith('--from'))) continue;
    for (const raw of words.filter((w) => !w.startsWith('--')).slice(0, -1)) {
      if (/[*?$]|^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('/')) continue;
      const s = posix.normalize(raw).replace(/\/+$/, '');
      if (s === '.' || s === '' || s.startsWith('..')) continue;
      sources.push(s);
    }
  }
  // the build context is the Dockerfile's folder when some source is found there, else the repo root
  const inOwn = dockerDir !== '.' && sources.some((s) => has(inDir(dockerDir, s)));
  return sources.map((s) => (inOwn ? inDir(dockerDir, s) : s));
}

/**
 * Whether another service's Dockerfile copies the whole of `dir` into its image. P57 (I1): one file out of the folder
 * (an openapi.json) doesn't make it part of that image, and a Dockerfile that belongs to no service (docker/api.Dockerfile
 * copying apps/api) may be the folder's own.
 */
function builtIntoAnImage(dir: string, copies: readonly DockerCopy[], serviceDirs: readonly string[]): boolean {
  if (dir === '.') return false;
  return copies.some((c) => c.dockerDir !== dir && !c.dockerDir.startsWith(`${dir}/`) && c.source === dir && serviceDirs.includes(c.dockerDir));
}

/** The one file `node [--flags] file.js` runs, repo-relative, or null for any other script text. */
function nodeEntry(dir: string, text: string): string | null {
  if (text.length > 300 || !regexSafe(text)) return null;
  const m = /^node\s+((?:--[a-z][a-z0-9-]*(?:=[A-Za-z0-9._-]+)?\s+)*)(\.?\/?[A-Za-z0-9_@][A-Za-z0-9_./-]*\.(?:js|mjs|cjs))$/.exec(text.trim());
  if (m === null) return null;
  const path = posix.normalize(posix.join(dir, m[2] as string));
  return path.startsWith('../') || path === '..' || path.split('/').includes('..') ? null : path;
}

type Reader = (rel: string) => Promise<string | null>;

/**
 * The relative modules a file's lines import, or null when the file can't be shown to start nothing: a line too long
 * to read (it could hide an import), a computed import, a package that isn't a quiet Node built-in, or text that
 * starts or keeps something running.
 */
function importsOf(lines: readonly string[]): string[] | null {
  const rel: string[] = [];
  const names = new Set<string>();
  for (const line of lines) for (const m of line.matchAll(FUNCTION_NAME_RE)) names.add((m[1] ?? m[2]) as string);
  for (const line of lines) {
    if (LONG_RUNNING_RE.test(line) || LOOP_RE.test(line)) return null;
    // a declared function named again (a call; inside its own body it is recursion): pipegen doesn't tell which
    // the declaration itself (`function poll(`) is not a call; anything else naming it is
    if (names.size > 0) for (const m of line.replace(/\bfunction\s*\*?\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\(/g, 'function (').matchAll(CALL_RE)) if (names.has(m[1] as string)) return null;
    if (/\b(?:import|require)\s*\(\s*(?!['"])/.test(line)) return null; // a computed import
    const specs = [...line.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g), ...line.matchAll(/^\s*import\s+['"]([^'"]+)['"]/g), ...line.matchAll(/\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]/g)];
    for (const [, spec] of specs) {
      if ((spec as string).startsWith('.')) rel.push(spec as string);
      else {
        const name = (spec as string).replace(/^node:/, '').split('/')[0] as string;
        if (!BUILTINS.has(name) || LONG_RUNNING_BUILTINS.has(name)) return null;
      }
    }
  }
  return rel;
}

/** Whether `entry` and the repo files it imports provably start nothing that keeps running. */
async function isOneShot(entry: string, read: Reader, fileSet: ReadonlySet<string>): Promise<boolean> {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift() as string;
    if (seen.has(file)) continue;
    if (seen.size >= MAX_ONE_SHOT_FILES || !fileSet.has(file)) return false;
    seen.add(file);
    const text = await read(file);
    if (text === null || text.length > MAX_ONE_SHOT_BYTES) return false;
    const lines = text.split(/\r?\n/);
    if (!lines.every(regexSafe)) return false;
    const rels = importsOf(lines);
    if (rels === null) return false;
    for (const spec of rels) {
      const base = posix.normalize(posix.join(dirOf(file), spec));
      if (base.startsWith('../') || base === '..') return false;
      const next = [base, `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`].find((c) => fileSet.has(c));
      if (next === undefined) return false;
      queue.push(next);
    }
  }
  return true;
}

export interface KindInput {
  dir: string; read: Reader; fileSet: ReadonlySet<string>; copies: readonly DockerCopy[];
  scripts: Obj; deps: Obj; devDeps: Obj; frameworks: readonly string[]; hasDockerfile: boolean; port: number | undefined; language: string;
  /** P57 (I1): every service folder of the repo, so only a service's own Dockerfile can build a folder into its image. */
  serviceDirs: readonly string[];
}

/** Why this folder isn't a standalone service, or undefined (the folder keeps the runnable test of isRunnable). */
export async function notStandaloneOf(k: KindInput): Promise<NotStandalone | undefined> {
  if (k.hasDockerfile || k.frameworks.length > 0 || k.language !== 'node') return undefined;
  const names = new Set([...Object.keys(k.deps), ...Object.keys(k.devDeps)]);
  // P57 (I1): a port found, or a server dependency, and it is a server, whatever else it uses
  if (k.port !== undefined || SERVER_DEPS.some((d) => names.has(d))) return undefined;
  const run = RUN_SCRIPTS.filter((n) => n in k.scripts);
  if (EMAIL_TOOLS.some((t) => names.has(t)) && run.length > 0 && run.every((n) => EMAIL_CLI_RE.test((asString(k.scripts[n]) ?? '').trim()))) return 'email-templates';
  if (builtIntoAnImage(k.dir, k.copies, k.serviceDirs)) return 'built-in-image';
  if (run.length === 0) return undefined;
  for (const n of run) {
    const entry = nodeEntry(k.dir, asString(k.scripts[n]) ?? '');
    if (entry === null || !(await isOneShot(entry, k.read, k.fileSet))) return undefined;
  }
  return 'one-shot';
}

/** The Dockerfiles of the repo (Dockerfile, Dockerfile.x, x.Dockerfile), at most MAX_DOCKERFILES, sorted. */
export function dockerfilesOf(fileSet: ReadonlySet<string>): string[] {
  return [...fileSet].filter((f) => /^(?:Dockerfile(?:\.[A-Za-z0-9_.-]+)?|[A-Za-z0-9_.-]+\.Dockerfile)$/.test(baseOf(f))).sort().slice(0, MAX_DOCKERFILES);
}

/**
 * Plan J J2 (ruling S1): the runnable test of isRunnable before project types (src/engine/needs.ts re-exports it). A start, dev or serve script,
 * a server framework, a port, or a Dockerfile; never a folder that isn't standalone (P55). Plan U Task 5: a package the repo publishes needs a
 * real server entry (a script, a framework or a Dockerfile); a port number in its code alone (Flask's `app.run(port=5000)` default) doesn't
 * make it one. The `server` type is this test on a service that isn't static.
 */
export function baseRunnable(s: Pick<Service, 'notStandalone' | 'scripts' | 'frameworks' | 'port' | 'publishedPackage' | 'dockerfile'>): boolean {
  if (s.notStandalone !== undefined) return false; // P55 (batch B): a one-shot script, built into another image, or an email-template package
  return s.scripts.some((n) => RUN_SCRIPTS.includes(n)) || s.frameworks.length > 0 || (s.port !== undefined && s.publishedPackage !== true)
    || (s.dockerfile ?? '') !== '';
}
