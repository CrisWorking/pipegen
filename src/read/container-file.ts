// GJ-R2 (reviews GJ sec I1, GJ-r1 N1, N2, N4): which files build a container image, and which of them builds a service folder. A leaf: names
// and paths only, never file content (the COPY sources come from the caller's copySources pass; the workflow references from the raw text
// of the repo's workflow files, read as text and never run).
//
// A container file: `Dockerfile` or `Containerfile` alone or with a `.`, `-` or `_` suffix, or `<x>.dockerfile` / `<x>.containerfile`, any
// case; a name that is clearly not built (a backup, a template, a sample, docs, a .dockerignore) is not one. Used by service finding, the
// service's own Dockerfile (the folder's own file), the COPY pass, and the container hint (a file deeper in the folder, a workflow that builds
// it, a container file elsewhere that copies it): a hint makes a static decision unsure (a server), never the static skip.
import { posix } from 'node:path';
import { READ_LIMITS, regexLines, regexSafe } from './limits.js';
import { baseOf, dirOf, PLAIN_PATH_RE } from './manifest.js';

/** A path as the hint shows it: a plain repo path, else a fixed word (no repo text reaches the evidence, S14). */
const plain = (p: string): string => (PLAIN_PATH_RE.test(p) ? p : 'a file');

const NAME_RE = /^(?:(?:dockerfile|containerfile)(?:[._-].+)?|.+\.(?:dockerfile|containerfile))$/i;
// GJ-R3 (nit): .j2 .tpl .in .dist are templates too
const NOT_BUILT_RE = /\.(?:bak|orig|template|tmpl|example|sample|md|txt|dockerignore|j2|tpl|in|dist)$/i;
/** Folder names whose container files never build the service around them (tests, fixtures, docs, vendored code). */
// GJ-R3 (O3): and the usual example, end-to-end, story, script, demo, sample and benchmark folders
export const NOT_BUILD_DIRS: readonly string[] = Object.freeze(['.devcontainer', 'test', 'tests', '__tests__', 'fixtures', 'examples', 'docs', 'vendor', 'node_modules',
  'example', 'e2e', 'playwright', 'cypress', '.storybook', 'scripts', 'demo', 'samples', 'testdata', 'benchmark']);

/** Whether a file name (no folder) is a container file. */
export const isContainerFileName = (name: string): boolean => NAME_RE.test(name) && !NOT_BUILT_RE.test(name);

/** G17 row 66 (B2): the container files of a file set, by folder and by every folder above them, built once per set (rebuilt when it grows). */
interface FileIndex { size: number; own: Map<string, string[]>; below: Map<string, string[]> }
const fileIndexes = new WeakMap<object, FileIndex>();
const sizeOf = (files: Iterable<string>): number => (files instanceof Set ? files.size : Array.isArray(files) ? files.length : -1);
/** The folders above `d`, nearest first, ending with `.` (none for `.`). */
function* ancestors(d: string): Generator<string> {
  for (let x = d; x !== '.'; ) { x = dirOf(x); yield x; }
}
function fileIndexOf(files: Iterable<string>): FileIndex {
  const size = sizeOf(files);
  const cached = size >= 0 ? fileIndexes.get(files as object) : undefined;
  if (cached !== undefined && cached.size === size) return cached;
  const own = new Map<string, string[]>();
  const below = new Map<string, string[]>();
  const push = (m: Map<string, string[]>, k: string, v: string): void => { const l = m.get(k); if (l === undefined) m.set(k, [v]); else l.push(v); };
  for (const f of files) {
    if (!isContainerFileName(baseOf(f))) continue;
    const d = dirOf(f);
    push(own, d, f);
    for (const a of ancestors(d)) push(below, a, f);
  }
  for (const l of own.values()) l.sort();
  const index = { size, own, below };
  if (size >= 0) fileIndexes.set(files as object, index);
  return index;
}

/** The container files directly in `dir` (never a sub-folder), sorted. */
export function containerFilesIn(files: Iterable<string>, dir: string): string[] {
  return [...(fileIndexOf(files).own.get(dir) ?? [])];
}

/**
 * The folder's own container file: the one a workflow builds (`built`), else a plain `Dockerfile`, else the first by name. `note` names the
 * chosen file and the others when there is more than one (N4: pipegen builds and scans one image per service, so the user sees which).
 */
// GJ-R4 (N4): a workflow's build first, then a plain Dockerfile, then a compose or bake file's build (often a dev image), then by name
export function chooseContainerFile(candidates: readonly string[], built: ReadonlySet<string>, composed: ReadonlySet<string> = new Set()): { file: string; note: string | null } | undefined {
  if (candidates.length === 0) return undefined;
  const byWorkflow = candidates.find((c) => built.has(c));
  const plainDf = candidates.find((c) => baseOf(c) === 'Dockerfile');
  const byBuildFile = candidates.find((c) => composed.has(c));
  const [file, why] = byWorkflow !== undefined ? [byWorkflow, 'the one a workflow builds']
    : plainDf !== undefined ? [plainDf, 'the plain Dockerfile']
      : byBuildFile !== undefined ? [byBuildFile, 'the one a compose or bake file builds']
        : [candidates[0] as string, 'the first by name; no workflow, compose or bake file builds one of them'];
  const note = candidates.length > 1 ? `${dirOf(file) === '.' ? 'The repository root' : `The folder ${plain(dirOf(file))}`} has several container files (${candidates.map(plain).join(', ')}); pipegen builds and scans ${plain(file)} (${why}).` : null;
  return { file, note };
}

/** A repo-relative path as a workflow writes it: no leading `./`, no trailing `/`; `.` for the root. */
// GJ-R-sec1: no regex runs over an unbounded string (trailing slashes trimmed by a loop; the value is a capture of one bounded line)
function norm(p: string): string {
  let x = p.replace(/^["']|["']$/g, '').replace(/^(?:\.\/)+/, '');
  let end = x.length;
  while (end > 0 && x.charCodeAt(end - 1) === 47) end--;
  x = x.slice(0, end);
  return x === '' ? '.' : x;
}
const FLAG_WITH_VALUE = new Set(['-t', '--tag', '--build-arg', '--platform', '--target', '--label', '--secret', '--cache-from', '--cache-to', '--output', '-o', '--network', '--progress']);
/** G17 row 73 (e): what stands for a `;`, `&` or `|` inside quotes; a value holding it is no reference. */
const QSEP = '\u0001';

/**
 * The paths the workflows build from: the `-f`/`--file` value and the context argument of a `docker build` / `docker buildx build` /
 * `podman build` line, a `context:` key, and a `file:` key whose value has a container file name. Text only (a run line or a key on its own
 * line); anything odd is just not a reference. GJ-R3 (O2): a `-f` elsewhere (rm -f, kubectl apply -f) or a `file:` of another action
 * (a coverage report) is no build.
 */
export function workflowBuildRefs(texts: readonly string[], out: Set<string> = new Set<string>()): Set<string> {
  const plainValue = (v: string): boolean => !v.includes(EXPR) && !v.includes(QSEP) && regexSafe(v);
  const add = (v: string | undefined): void => { if (v !== undefined && plainValue(v)) out.add(norm(v)); };
  // G17 row 73 (a): a file path with an expression in it still names its folder (`-f apps/web/Dockerfile.${{ matrix.stage }}`)
  const addFile = (v: string | undefined): void => {
    if (v === undefined) return;
    const e = v.indexOf(EXPR);
    if (e < 0) { add(v); return; }
    const cut = v.lastIndexOf('/', e);
    if (cut > 0) add(v.slice(0, cut));
  };
  // GJ-R-sec1: line by line over regexLines (each line bounded, like the other parsers), `[ \t]*` at the anchor.
  // GJ-R4 (N1): `\`-continued lines are joined first, within the same per-line budget (a longer one is dropped whole)
  for (const t of texts) {
    for (const line of scanLines(t)) {
      const ctxKey = /^[ \t]*(?:-[ \t]+)?context:[ \t]*("[^"]+"|'[^']+'|[^\s"'#]+)/.exec(line);
      if (ctxKey !== null) add(ctxKey[1]);
      const fileKey = /^[ \t]*(?:-[ \t]+)?file:[ \t]*("[^"]+"|'[^']+'|[^\s"'#]+)/.exec(line);
      if (fileKey !== null && isContainerFileName(baseOf(norm(fileKey[1] as string)))) add(fileKey[1]);
      for (const m of line.matchAll(/\b(?:docker(?:[ \t]+buildx)?|podman)[ \t]+build\b([^&|;]*)/g)) {
        const words = (m[1] as string).trim().split(/[ \t]+/).filter((w) => w !== '');
        let ctx: string | undefined;
        for (let i = 0; i < words.length; i++) {
          const w = words[i] as string;
          if (w === '-f' || w === '--file') { addFile(words[i + 1]); i++; continue; }
          if (w.startsWith('--file=') || w.startsWith('-f=')) { addFile(w.slice(w.indexOf('=') + 1)); continue; }
          if (FLAG_WITH_VALUE.has(w)) { i++; continue; }
          if (w.startsWith('-')) continue;
          ctx = w;
        }
        add(ctx);
      }
    }
  }
  return out;
}

/** G17 row 68: a continued part made only of `--build-arg`/`--label`/`--annotation`/`--secret` values (no path); it never counts against the budget. */
const NOISE_PART_RE = /^[ \t]*(?:--(?:build-arg|label|annotation|secret)(?:=|[ \t]+)(?:"[^"]*"|[^\s"'\\]+))(?:[ \t]+--(?:build-arg|label|annotation|secret)(?:=|[ \t]+)(?:"[^"]*"|[^\s"'\\]+))*[ \t]*$/;
/** G17 row 69: a `run: >` (folded) block header. */
const FOLDED_RUN_RE = /^[ \t]*(?:-[ \t]+)?run:[ \t]*>[-+]?[1-9]?[-+]?[ \t]*(?:#.*)?$/;
const indentOf = (s: string): number => { let i = 0; while (i < s.length && (s.charCodeAt(i) === 32 || s.charCodeAt(i) === 9)) i++; return i; };

/**
 * The lines of `t` with shell `\` continuations joined; a joined line over the regex budget is dropped. Linear: no regex on unbounded text.
 * G17 row 68: a continued part of only `--build-arg`-like values is left out (its values are never paths), so a long chain keeps its path
 * words. G17 row 69: the lines of a folded `run: >` block are joined with spaces, as YAML folds them (a blank line ends a line; a more
 * indented line stays a line of its own).
 */
function joinedLines(t: string): string[] {
  const out: string[] = [];
  let acc = '';
  let bytes = 0;
  let over = false;
  const append = (part: string): void => {
    if (over) return;
    bytes += Buffer.byteLength(part) + 1;
    if (bytes > READ_LIMITS.maxRegexLineBytes) over = true;
    else acc += (acc === '' ? '' : ' ') + part;
  };
  const flush = (): void => {
    if (acc !== '' && !over) out.push(acc);
    acc = '';
    bytes = 0;
    over = false;
  };
  let fold: { parent: number; indent: number } | null = null;
  for (const raw of t.split('\n')) {
    let end = raw.length;
    while (end > 0 && (raw.charCodeAt(end - 1) === 32 || raw.charCodeAt(end - 1) === 9 || raw.charCodeAt(end - 1) === 13)) end--;
    const cont = end > 0 && raw.charCodeAt(end - 1) === 92;
    const part = cont ? raw.slice(0, end - 1) : raw.slice(0, end);
    if (fold !== null) {
      const ind = indentOf(part);
      if (ind >= part.length && !cont) { flush(); continue; }
      if (fold.indent < 0) fold.indent = ind > fold.parent ? ind : -2;
      if (fold.indent >= 0 && ind === fold.indent) { append(part.slice(ind)); continue; }
      if (fold.indent >= 0 && ind > fold.indent) { flush(); append(part); flush(); continue; }
      flush();
      fold = null;
    }
    if (acc !== '' && !over && Buffer.byteLength(part) <= READ_LIMITS.maxRegexLineBytes && NOISE_PART_RE.test(part)) { if (cont) continue; flush(); continue; }
    append(part);
    if (cont) continue;
    flush();
    if (end <= READ_LIMITS.maxRegexLineBytes && FOLDED_RUN_RE.test(part)) fold = { parent: indentOf(part), indent: -1 };
  }
  flush();
  return out;
}

/** GJ-R5 (H1): what stands for a `${{ … }}` or `$( … )` span; a value holding it is no reference. */
const EXPR = '\u0000';
const MAX_EXPR_DEPTH = 16;
const isWordChar = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const wordAt = (s: string, i: number, w: string): boolean => s.startsWith(w, i) && (i === 0 || !isWordChar(s.charCodeAt(i - 1))) && !isWordChar(s.charCodeAt(i + w.length));
/**
 * G17 row 73 (b, c): the matching `)` of each `(` of a (bounded) line, or -1. One pass with a stack; inside a `( … )` that has an open
 * `case` (until its `esac`), a `)` with no `(` of its own is a case pattern, not the end of the span.
 */
function parenMatches(line: string): Int32Array {
  const match = new Int32Array(line.length).fill(-1);
  const stack: { pos: number; cases: number }[] = [];
  for (let j = 0; j < line.length; j++) {
    const c = line.charCodeAt(j);
    if (c === 40) {
      stack.push({ pos: j, cases: 0 });
      // nesting deeper than MAX_EXPR_DEPTH: the outermost open span has no usable end (-2: blank the rest of the line, as GJ-R5)
      if (stack.length > MAX_EXPR_DEPTH) { match[(stack[0] as { pos: number }).pos] = -2; return match; }
    }
    else if (c === 41) {
      const top = stack[stack.length - 1];
      if (top === undefined) continue;
      if (top.cases > 0) continue;
      stack.pop();
      match[top.pos] = j;
    } else if (c === 99 && stack.length > 0 && wordAt(line, j, 'case')) (stack[stack.length - 1] as { cases: number }).cases++;
    else if (c === 101 && stack.length > 0 && wordAt(line, j, 'esac')) { const top = stack[stack.length - 1] as { cases: number }; if (top.cases > 0) top.cases--; }
  }
  return match;
}
/** G17 row 73 (k): the quoted fallback of a `${{ x || 'path' }}` expression, if that is its whole tail. */
const FALLBACK_RE = /\|\|[ \t]*'([^'${}]+)'[ \t]*$/;
/**
 * GJ-R5 (H1): each `${{ … }}`, `$( … )` and (G17 row 73 d) `` `…` `` span of a (bounded) line becomes one EXPR character, so an `||` or a
 * space inside it never ends a build line or splits a word. A character loop, no regex over the line. GJ-R6 (Ha): the inner text of each
 * `$( … )` and backtick span (blanked the same way) goes to `inner`, to be read as a line of its own; (perf) a line with no `$` or backtick
 * is returned as it is, and the text between spans is copied by slice. G17 row 73 (b): an unclosed `$(`, `${{` or backtick blanks only
 * itself; nesting deeper than MAX_EXPR_DEPTH still blanks the rest of the line (GJ-R5). (k) `${{ x || 'apps/web' }}` stands for its quoted fallback.
 */
function blankExpressions(line: string, inner: string[], depth = 0): string {
  const firstDollar = line.indexOf('$');
  const firstTick = line.indexOf('`');
  if (firstDollar < 0 && firstTick < 0) return line;
  let match: Int32Array | undefined;
  let out = '';
  let last = 0;
  const next = (from: number): number => {
    const d = line.indexOf('$', from);
    const b = line.indexOf('`', from);
    return d < 0 ? b : b < 0 ? d : Math.min(d, b);
  };
  const span = (from: number, to: number): void => { if (depth < MAX_EXPR_DEPTH) inner.push(blankExpressions(line.slice(from, to), inner, depth + 1)); };
  let i = firstDollar < 0 ? firstTick : firstTick < 0 ? firstDollar : Math.min(firstDollar, firstTick);
  while (i >= 0) {
    if (line.charCodeAt(i) === 96) {
      const j = line.indexOf('`', i + 1);
      if (j < 0) { i = next(i + 1); continue; }
      span(i + 1, j);
      out += line.slice(last, i) + EXPR;
      last = j + 1;
      i = next(last);
      continue;
    }
    if (line.startsWith('${{', i)) {
      const j = line.indexOf('}}', i + 3);
      if (j < 0) { out += line.slice(last, i) + EXPR; last = i + 3; i = next(last); continue; }
      const fallback = FALLBACK_RE.exec(line.slice(i + 3, j));
      out += line.slice(last, i) + (fallback !== null ? (fallback[1] as string).trim() : EXPR);
      last = j + 2;
      i = next(last);
      continue;
    }
    if (line.charCodeAt(i + 1) === 40) {
      match ??= parenMatches(line);
      const j = match[i + 1] as number;
      if (j === -2) return out + line.slice(last, i) + EXPR;
      if (j < 0) { out += line.slice(last, i) + EXPR; last = i + 2; i = next(last); continue; }
      span(i + 2, j);
      out += line.slice(last, i) + EXPR;
      last = j + 1;
      i = next(last);
      continue;
    }
    i = next(i + 1);
  }
  return out + line.slice(last);
}

/** G17 row 73 (e): a `;`, `&` or `|` inside a quoted word becomes QSEP, so it never ends a build line. A quote opens only at a word start. */
function protectQuoted(line: string): string {
  if (!/["']/.test(line) || !/[;&|]/.test(line)) return line;
  let out = '';
  let last = 0;
  for (let k = 0; k < line.length; k++) {
    const c = line[k];
    if (c !== '"' && c !== "'") continue;
    const prev = k === 0 ? ' ' : (line[k - 1] as string);
    if (!/[\s=(]/.test(prev)) continue;
    const close = line.indexOf(c, k + 1);
    if (close < 0) break;
    out += line.slice(last, k) + line.slice(k, close + 1).replace(/[;&|]/g, QSEP);
    last = close + 1;
    k = close;
  }
  return out + line.slice(last);
}

/** The joined lines of `t` with expressions blanked, each followed by the inner texts of its `$( … )` spans (GJ-R6 Ha). */
function scanLines(t: string): string[] {
  const out: string[] = [];
  for (const l of joinedLines(t)) {
    const inner: string[] = [];
    out.push(protectQuoted(blankExpressions(l, inner)), ...inner.map(protectQuoted));
  }
  return out;
}

/**
 * A path a compose or bake file names, relative to that file's folder, as a repo path; undefined when it leaves the repo or is not plain.
 * G17 row 67 (N6): a `${VAR:-default}` / `${VAR-default}` takes its default, and a bake `${NAME}` its variable's default (`vars`); any
 * other `$` is no reference.
 */
function fromBuildFile(fileDir: string, rel: unknown, vars: ReadonlyMap<string, string> = new Map()): string | undefined {
  if (typeof rel !== 'string' || rel === '' || !regexSafe(rel)) return undefined;
  const v = rel.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}$]*))?\}/g, (whole, name: string, dflt: string | undefined) => dflt ?? vars.get(name) ?? whole);
  if (v === '' || v.includes('$') || v.includes('://') || posix.isAbsolute(v)) return undefined;
  const p = posix.normalize(posix.join(fileDir, norm(v)));
  return p === '..' || p.startsWith('../') ? undefined : norm(p);
}

const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
/** G17 row 67 (N6): a mapping with its YAML `<<` merge keys applied (its own keys win, then the merged maps in order); bounded depth. */
function merged(x: unknown, depth = 0): unknown {
  if (!isObj(x) || !('<<' in x) || depth > 8) return x;
  const srcs = Array.isArray(x['<<']) ? (x['<<'] as unknown[]) : [x['<<']];
  const res: Record<string, unknown> = {};
  for (const s of [...srcs].reverse()) { const m = merged(s, depth + 1); if (isObj(m)) Object.assign(res, m); }
  for (const [k, v] of Object.entries(x)) if (k !== '<<') res[k] = v;
  delete res['<<'];
  return res;
}

/** GJ-R3 (H1 b): the build contexts (and the container files in them) a parsed compose file names: `build: <ctx>` or `build: { context, dockerfile }`. */
export function composeBuildRefs(file: string, doc: unknown, out: Set<string>): void {
  const services = (doc as { services?: unknown } | null)?.services;
  if (services === null || typeof services !== 'object') return;
  for (const svc of Object.values(services as Record<string, unknown>)) {
    const build = (merged(svc) as { build?: unknown } | null)?.build;
    const mb = merged(build);
    const b = typeof mb === 'string' ? { context: mb } : isObj(mb) ? (mb as { context?: unknown; dockerfile?: unknown }) : undefined;
    if (b === undefined) continue;
    addBuild(dirOf(file), b, out);
  }
}

function addBuild(fileDir: string, b: { context?: unknown; dockerfile?: unknown }, out: Set<string>, vars?: ReadonlyMap<string, string>): void {
  const ctx = fromBuildFile(fileDir, b.context ?? '.', vars);
  if (ctx === undefined) return;
  out.add(ctx);
  const df = fromBuildFile(ctx, b.dockerfile, vars);
  if (df !== undefined) out.add(df);
}

/**
 * GJ-R3 (H1 b): the build contexts (and container files) of a bake file's `target` blocks (`context = "…"`, `dockerfile = "…"`), read as
 * text. G17 row 67 (N6): a one-line `target "x" { context = "…" }` counts, and `${NAME}` takes a `variable "NAME" { default = "…" }`.
 */
export function bakeBuildRefs(file: string, text: string, out: Set<string>): void {
  const lines = regexLines(text);
  const vars = new Map<string, string>();
  let variable: string | null = null;
  for (const line of lines) {
    const head = /^[ \t]*(\w+)[ \t]+"([^"]*)"/.exec(line);
    if (head !== null) variable = head[1] === 'variable' ? (head[2] as string) : null;
    const d = /\bdefault[ \t]*=[ \t]*"([^"]*)"/.exec(line);
    if (d !== null && variable !== null && !vars.has(variable)) vars.set(variable, d[1] as string);
  }
  let target: { context?: string; dockerfile?: string } | null = null;
  const flush = (): void => {
    if (target !== null) addBuild(dirOf(file), target, out, vars);
    target = null;
  };
  for (const line of lines) {
    const head = /^[ \t]*(\w+)[ \t]+"/.exec(line);
    if (head !== null) { flush(); if (head[1] === 'target') target = {}; }
    if (target === null) continue;
    for (const kv of line.matchAll(/\b(context|dockerfile)[ \t]*=[ \t]*"([^"]*)"/g)) target[kv[1] as 'context' | 'dockerfile'] = kv[2] as string;
  }
  flush();
}

/** G17 row 67 (N6): the same for a parsed `docker-bake.json` (`target` and `variable` objects). */
export function bakeJsonBuildRefs(file: string, doc: unknown, out: Set<string>): void {
  if (!isObj(doc)) return;
  const vars = new Map<string, string>();
  if (isObj(doc.variable)) for (const [k, v] of Object.entries(doc.variable)) if (isObj(v) && typeof v.default === 'string') vars.set(k, v.default);
  if (!isObj(doc.target)) return;
  for (const t of Object.values(doc.target)) if (isObj(t)) addBuild(dirOf(file), t, out, vars);
}

const under = (path: string, dir: string): boolean => dir === '.' || path === dir || path.startsWith(`${dir}/`);

/** GJ-R3 (H1 a): a link name that may be a folder (no extension): pipegen never follows a link, so it can't tell. */
const folderLike = (name: string): boolean => /^\.?[^.]+$/.test(name);

/** G17 row 66 (B2): the links that can be a hint (a container file name or a folder's name), by every folder above them; once per list. */
const linkIndexes = new WeakMap<readonly string[], Map<string, string[]>>();
function linkIndexOf(links: readonly string[]): Map<string, string[]> {
  const cached = linkIndexes.get(links);
  if (cached !== undefined) return cached;
  const m = new Map<string, string[]>();
  for (const l of links) {
    if (!regexSafe(l)) continue;
    const b = baseOf(l);
    if (!isContainerFileName(b) && !folderLike(b)) continue;
    for (const a of ancestors(l)) { const x = m.get(a); if (x === undefined) m.set(a, [l]); else x.push(l); }
  }
  linkIndexes.set(links, m);
  return m;
}

/**
 * GJ-R2 (N1): why a service folder with no container file of its own is built into an image anyway, or undefined: a container file deeper in
 * the folder (outside NOT_BUILD_DIRS and other services' folders), a symbolic link in it with a container file name or a folder's name (by
 * name only, never followed; GJ-R3 H1 a), a workflow, compose or bake file that builds from the folder (a context or file path in it), or a
 * container file elsewhere that copies the folder. The text names the file or the reference (plain repo paths only).
 * G17 row 66 (B2): the files and links are looked up by folder (indexes built once), never scanned whole per folder.
 */
export function containerHintOf(dir: string, files: Iterable<string>, serviceDirs: readonly string[], refs: ReadonlySet<string>, copies: readonly { file: string; source: string }[], links: readonly string[] = []): string | undefined {
  const others = new Set(serviceDirs.filter((d) => d !== dir && under(d, dir) && d !== '.'));
  const rel = (f: string): string[] => (dir === '.' ? f : f.slice(dir.length + 1)).split('/');
  // in `dir` and in no other service folder below it: the folders between the path and `dir` are not services
  const inScope = (f: string): boolean => {
    if (!under(f, dir) || f === dir) return false;
    if (others.size === 0) return true;
    for (let d = f; d !== dir && d !== '.'; d = dirOf(d)) if (others.has(d)) return false;
    return true;
  };
  const deep = (fileIndexOf(files).below.get(dir) ?? []).filter((f) => inScope(f) && !rel(dirOf(f)).some((seg) => NOT_BUILD_DIRS.includes(seg))).sort();
  if (deep.length > 0) return `a container file builds it: ${deep.map(plain).join(', ')}`;
  const linked = (linkIndexOf(links).get(dir) ?? []).filter((l) => inScope(l) && !(dirOf(l) === dir ? [] : rel(dirOf(l))).some((seg) => NOT_BUILD_DIRS.includes(seg)));
  const linkedFiles = linked.filter((l) => isContainerFileName(baseOf(l))).sort();
  if (linkedFiles.length > 0) return `a container file builds it: ${linkedFiles.map(plain).join(', ')} (a symbolic link, which pipegen does not follow)`;
  const linkedDirs = linked.filter((l) => folderLike(baseOf(l)) && !NOT_BUILD_DIRS.includes(baseOf(l))).sort();
  if (linkedDirs.length > 0) return `a linked folder may hold the container file that builds it: ${linkedDirs.map(plain).join(', ')} (a symbolic link, which pipegen does not follow)`;
  const ref = [...refs].filter((r) => (dir === '.' ? r === '.' || (dirOf(r) === '.' && isContainerFileName(r)) : under(r, dir))).sort();
  if (ref.length > 0) return `a workflow, compose or bake file builds an image from it: ${ref.map(plain).join(', ')}`;
  if (dir !== '.') {
    const copy = [...new Set(copies.filter((c) => dirOf(c.file) !== dir && under(c.source, dir)).map((c) => c.file))].sort();
    if (copy.length > 0) return `a container file copies it into an image: ${copy.map(plain).join(', ')}`;
  }
  return undefined;
}
