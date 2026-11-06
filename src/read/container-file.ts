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

/** The container files directly in `dir` (never a sub-folder), sorted. */
export function containerFilesIn(files: Iterable<string>, dir: string): string[] {
  const out: string[] = [];
  for (const f of files) if (dirOf(f) === dir && isContainerFileName(baseOf(f))) out.push(f);
  return out.sort();
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

/**
 * The paths the workflows build from: the `-f`/`--file` value and the context argument of a `docker build` / `docker buildx build` /
 * `podman build` line, a `context:` key, and a `file:` key whose value has a container file name. Text only (a run line or a key on its own
 * line); anything odd is just not a reference. GJ-R3 (O2): a `-f` elsewhere (rm -f, kubectl apply -f) or a `file:` of another action
 * (a coverage report) is no build.
 */
export function workflowBuildRefs(texts: readonly string[], out: Set<string> = new Set<string>()): Set<string> {
  const add = (v: string | undefined): void => { if (v !== undefined && regexSafe(v)) out.add(norm(v)); };
  // GJ-R-sec1: line by line over regexLines (each line bounded, like the other parsers), `[ \t]*` at the anchor.
  // GJ-R4 (N1): `\`-continued lines are joined first, within the same per-line budget (a longer one is dropped whole)
  for (const t of texts) {
    for (const line of joinedLines(t)) {
      const ctxKey = /^[ \t]*(?:-[ \t]+)?context:[ \t]*("[^"]+"|'[^']+'|[^\s"'#]+)/.exec(line);
      if (ctxKey !== null) add(ctxKey[1]);
      const fileKey = /^[ \t]*(?:-[ \t]+)?file:[ \t]*("[^"]+"|'[^']+'|[^\s"'#]+)/.exec(line);
      if (fileKey !== null && isContainerFileName(baseOf(norm(fileKey[1] as string)))) add(fileKey[1]);
      for (const m of line.matchAll(/\b(?:docker(?:[ \t]+buildx)?|podman)[ \t]+build\b([^&|;]*)/g)) {
        const words = (m[1] as string).trim().split(/[ \t]+/).filter((w) => w !== '');
        let ctx: string | undefined;
        for (let i = 0; i < words.length; i++) {
          const w = words[i] as string;
          if (w === '-f' || w === '--file') { add(words[i + 1]); i++; continue; }
          if (w.startsWith('--file=') || w.startsWith('-f=')) { add(w.slice(w.indexOf('=') + 1)); continue; }
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

/** The lines of `t` with shell `\` continuations joined; a joined line over the regex budget is dropped. Linear: no regex on unbounded text. */
function joinedLines(t: string): string[] {
  const out: string[] = [];
  let acc = '';
  let bytes = 0;
  let over = false;
  for (const raw of t.split('\n')) {
    let end = raw.length;
    while (end > 0 && (raw.charCodeAt(end - 1) === 32 || raw.charCodeAt(end - 1) === 9 || raw.charCodeAt(end - 1) === 13)) end--;
    const cont = end > 0 && raw.charCodeAt(end - 1) === 92;
    const part = cont ? raw.slice(0, end - 1) : raw.slice(0, end);
    if (!over) {
      bytes += Buffer.byteLength(part) + 1;
      if (bytes > READ_LIMITS.maxRegexLineBytes) over = true;
      else acc += (acc === '' ? '' : ' ') + part;
    }
    if (cont) continue;
    if (!over) out.push(acc);
    acc = '';
    bytes = 0;
    over = false;
  }
  if (acc !== '' && !over) out.push(acc);
  return out;
}

/** A path a compose or bake file names, relative to that file's folder, as a repo path; undefined when it leaves the repo or is not plain. */
function fromBuildFile(fileDir: string, rel: unknown): string | undefined {
  if (typeof rel !== 'string' || rel === '' || !regexSafe(rel) || rel.includes('$') || rel.includes('://') || posix.isAbsolute(rel)) return undefined;
  const p = posix.normalize(posix.join(fileDir, norm(rel)));
  return p === '..' || p.startsWith('../') ? undefined : norm(p);
}

/** GJ-R3 (H1 b): the build contexts (and the container files in them) a parsed compose file names: `build: <ctx>` or `build: { context, dockerfile }`. */
export function composeBuildRefs(file: string, doc: unknown, out: Set<string>): void {
  const services = (doc as { services?: unknown } | null)?.services;
  if (services === null || typeof services !== 'object') return;
  for (const svc of Object.values(services as Record<string, unknown>)) {
    const build = (svc as { build?: unknown } | null)?.build;
    const b = typeof build === 'string' ? { context: build } : build !== null && typeof build === 'object' ? (build as { context?: unknown; dockerfile?: unknown }) : undefined;
    if (b === undefined) continue;
    const ctx = fromBuildFile(dirOf(file), b.context ?? '.');
    if (ctx === undefined) continue;
    out.add(ctx);
    const df = fromBuildFile(ctx, b.dockerfile);
    if (df !== undefined) out.add(df);
  }
}

/** GJ-R3 (H1 b): the build contexts (and container files) of a bake file's `target` blocks (`context = "…"`, `dockerfile = "…"`), read as text. */
export function bakeBuildRefs(file: string, text: string, out: Set<string>): void {
  let target: { context?: string; dockerfile?: string } | null = null;
  const flush = (): void => {
    if (target === null) return;
    const ctx = fromBuildFile(dirOf(file), target.context ?? '.');
    if (ctx !== undefined) {
      out.add(ctx);
      const df = fromBuildFile(ctx, target.dockerfile);
      if (df !== undefined) out.add(df);
    }
    target = null;
  };
  for (const line of regexLines(text)) {
    if (/^[ \t]*target[ \t]+"/.test(line)) { flush(); target = {}; continue; }
    const kv = /^[ \t]*(context|dockerfile)[ \t]*=[ \t]*"([^"]*)"/.exec(line);
    if (kv !== null && target !== null) target[kv[1] as 'context' | 'dockerfile'] = kv[2] as string;
  }
  flush();
}

const under = (path: string, dir: string): boolean => dir === '.' || path === dir || path.startsWith(`${dir}/`);

/** GJ-R3 (H1 a): a link name that may be a folder (no extension): pipegen never follows a link, so it can't tell. */
const folderLike = (name: string): boolean => /^\.?[^.]+$/.test(name);

/**
 * GJ-R2 (N1): why a service folder with no container file of its own is built into an image anyway, or undefined: a container file deeper in
 * the folder (outside NOT_BUILD_DIRS and other services' folders), a symbolic link in it with a container file name or a folder's name (by
 * name only, never followed; GJ-R3 H1 a), a workflow, compose or bake file that builds from the folder (a context or file path in it), or a
 * container file elsewhere that copies the folder. The text names the file or the reference (plain repo paths only).
 */
export function containerHintOf(dir: string, files: Iterable<string>, serviceDirs: readonly string[], refs: ReadonlySet<string>, copies: readonly { file: string; source: string }[], links: readonly string[] = []): string | undefined {
  const others = serviceDirs.filter((d) => d !== dir && under(d, dir) && d !== '.');
  const rel = (f: string): string[] => (dir === '.' ? f : f.slice(dir.length + 1)).split('/');
  const inScope = (f: string): boolean => under(f, dir) && f !== dir && !others.some((o) => under(f, o));
  const deep = [...files].filter((f) => inScope(f) && dirOf(f) !== dir && isContainerFileName(baseOf(f))
    && !rel(dirOf(f)).some((seg) => NOT_BUILD_DIRS.includes(seg))).sort();
  if (deep.length > 0) return `a container file builds it: ${deep.map(plain).join(', ')}`;
  const linked = links.filter((l) => regexSafe(l) && inScope(l) && !(dirOf(l) === dir ? [] : rel(dirOf(l))).some((seg) => NOT_BUILD_DIRS.includes(seg)));
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
