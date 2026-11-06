// GJ-R2 (reviews GJ sec I1, GJ-r1 N1, N2, N4): which files build a container image, and which of them builds a service folder. A leaf: names
// and paths only, never file content (the COPY sources come from the caller's copySources pass; the workflow references from the raw text
// of the repo's workflow files, read as text and never run).
//
// A container file: `Dockerfile` or `Containerfile` alone or with a `.`, `-` or `_` suffix, or `<x>.dockerfile` / `<x>.containerfile`, any
// case; a name that is clearly not built (a backup, a template, a sample, docs, a .dockerignore) is not one. Used by service finding, the
// service's own Dockerfile (the folder's own file), the COPY pass, and the container hint (a file deeper in the folder, a workflow that builds
// it, a container file elsewhere that copies it): a hint makes a static decision unsure (a server), never the static skip.
import { baseOf, dirOf, PLAIN_PATH_RE } from './manifest.js';

/** A path as the hint shows it: a plain repo path, else a fixed word (no repo text reaches the evidence, S14). */
const plain = (p: string): string => (PLAIN_PATH_RE.test(p) ? p : 'a file');

const NAME_RE = /^(?:(?:dockerfile|containerfile)(?:[._-].+)?|.+\.(?:dockerfile|containerfile))$/i;
const NOT_BUILT_RE = /\.(?:bak|orig|template|tmpl|example|sample|md|txt|dockerignore)$/i;
/** Folder names whose container files never build the service around them (tests, fixtures, docs, vendored code). */
export const NOT_BUILD_DIRS: readonly string[] = Object.freeze(['.devcontainer', 'test', 'tests', '__tests__', 'fixtures', 'examples', 'docs', 'vendor', 'node_modules']);

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
export function chooseContainerFile(candidates: readonly string[], built: ReadonlySet<string>): { file: string; note: string | null } | undefined {
  if (candidates.length === 0) return undefined;
  const byWorkflow = candidates.filter((c) => built.has(c));
  const plainDf = candidates.find((c) => baseOf(c) === 'Dockerfile');
  const [file, why] = byWorkflow.length > 0 ? [byWorkflow[0] as string, 'the one a workflow builds'] : plainDf !== undefined ? [plainDf, 'the plain Dockerfile'] : [candidates[0] as string, 'the first by name; no workflow builds one of them'];
  const note = candidates.length > 1 ? `${dirOf(file) === '.' ? 'The repository root' : `The folder ${plain(dirOf(file))}`} has several container files (${candidates.map(plain).join(', ')}); pipegen builds and scans ${plain(file)} (${why}).` : null;
  return { file, note };
}

/** A repo-relative path as a workflow writes it: no leading `./`, no trailing `/`; `.` for the root. */
const norm = (p: string): string => { const x = p.replace(/^["']|["']$/g, '').replace(/^(?:\.\/)+/, '').replace(/\/+$/, ''); return x === '' ? '.' : x; };
const FLAG_WITH_VALUE = new Set(['-t', '--tag', '--build-arg', '--platform', '--target', '--label', '--secret', '--cache-from', '--cache-to', '--output', '-o', '--network', '--progress']);

/**
 * The paths the workflows build from: `-f`/`--file` values, `file:` and `context:` keys, and the context argument of `docker build` /
 * `docker buildx build` / `podman build` lines. Text only (a run line or a key on its own line); anything odd is just not a reference.
 */
export function workflowBuildRefs(texts: readonly string[]): Set<string> {
  const out = new Set<string>();
  for (const t of texts) {
    for (const m of t.matchAll(/(?:^|\s)(?:-f|--file)(?:\s+|=)("[^"\n]+"|'[^'\n]+'|[^\s"';&|]+)/g)) out.add(norm(m[1] as string));
    for (const m of t.matchAll(/^\s*(?:-\s+)?(?:file|context):\s*("[^"\n]+"|'[^'\n]+'|[^\s"'#]+)/gm)) out.add(norm(m[1] as string));
    for (const m of t.matchAll(/\b(?:docker(?:\s+buildx)?|podman)\s+build\b([^\n&|;]*)/g)) {
      const words = (m[1] as string).trim().split(/\s+/).filter((w) => w !== '');
      let ctx: string | undefined;
      for (let i = 0; i < words.length; i++) {
        const w = words[i] as string;
        if (w === '-f' || w === '--file' || FLAG_WITH_VALUE.has(w)) { i++; continue; }
        if (w.startsWith('-')) continue;
        ctx = w;
      }
      if (ctx !== undefined) out.add(norm(ctx));
    }
  }
  return out;
}

const under = (path: string, dir: string): boolean => dir === '.' || path === dir || path.startsWith(`${dir}/`);

/**
 * GJ-R2 (N1): why a service folder with no container file of its own is built into an image anyway, or undefined: a container file deeper in
 * the folder (outside NOT_BUILD_DIRS and other services' folders), a workflow that builds from the folder (a context or file path in it), or
 * a container file elsewhere that copies the folder. The text names the file or the reference (plain repo paths only).
 */
export function containerHintOf(dir: string, files: Iterable<string>, serviceDirs: readonly string[], refs: ReadonlySet<string>, copies: readonly { file: string; source: string }[]): string | undefined {
  const others = serviceDirs.filter((d) => d !== dir && under(d, dir) && d !== '.');
  const deep = [...files].filter((f) => under(f, dir) && dirOf(f) !== dir && isContainerFileName(baseOf(f))
    && !others.some((o) => under(f, o))
    && !(dir === '.' ? dirOf(f) : dirOf(f).slice(dir.length + 1)).split('/').some((seg) => NOT_BUILD_DIRS.includes(seg))).sort();
  if (deep.length > 0) return `a container file builds it: ${deep.map(plain).join(', ')}`;
  if (dir !== '.') {
    const ref = [...refs].filter((r) => under(r, dir)).sort();
    if (ref.length > 0) return `a workflow builds an image from it: ${ref.map(plain).join(', ')}`;
    const copy = [...new Set(copies.filter((c) => dirOf(c.file) !== dir && under(c.source, dir)).map((c) => c.file))].sort();
    if (copy.length > 0) return `a container file copies it into an image: ${copy.map(plain).join(', ')}`;
  }
  return undefined;
}

