// Coverage mapper (see ../coverage.ts for the rules): reading the words of `docker build` and `docker compose …` command
// lines (P55, batch B). A leaf module: pure functions over the words, no I/O, no imports from the rest of the mapper, so
// shell.ts (which reads command lines) and docker.ts (which reads the Dockerfiles they build) can both use it.
//
// Only flags pipegen knows are read. Any other flag makes the command "unreadable" (null): it is still the build or the
// run it is, but pipegen doesn't guess which Dockerfile or service it names, so nothing inside it is credited.
// Flag lists: https://docs.docker.com/reference/cli/docker/buildx/build/ and
// https://docs.docker.com/reference/cli/docker/compose/ (checked 2026-10-29).

/** The word at index i of the command line being read, or null at its end. */
export type At = (i: number) => string | null;

const PATH_RE = /^[A-Za-z0-9_.][A-Za-z0-9_./-]*$/;
/** A plain relative path word (no variable, no quote, no `..` part, at most 200 characters), else null. */
export function plainPath(w: string | null | undefined): string | null {
  if (w === null || w === undefined || w.length > 200 || !PATH_RE.test(w) || w.split('/').some((p) => p === '..')) return null;
  return w;
}

// ---------- docker build ----------

const BUILD_VALUE: ReadonlySet<string> = new Set([
  '-f', '--file', '-t', '--tag', '--build-arg', '--target', '--platform', '--secret', '--ssh', '--cache-from', '--cache-to', '-o', '--output', '--label',
  '--network', '--progress', '--provenance', '--sbom', '--iidfile', '--add-host', '--build-context', '--builder', '--metadata-file', '--allow', '--attest',
  '--shm-size', '-m', '--memory', '--ulimit', '--cgroup-parent', '--no-cache-filter', '--annotation',
]);
const BUILD_BOOL: ReadonlySet<string> = new Set(['--no-cache', '--pull', '--push', '--load', '-q', '--quiet', '--rm', '--force-rm', '--compress', '--squash', '--debug', '-D', '--disable-content-trust']);

export interface BuildWords { file: string | null; context: string; target: string | null }
/** P57: Docker's own Dockerfile frontend (any tag or digest); any other BUILDKIT_SYNTAX or `# syntax=` picks a custom one. */
export const OFFICIAL_FRONTEND = /^(?:docker\.io\/)?docker\/dockerfile(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$/;
/** P57 (M3): a build arg that picks the frontend: only Docker's own, as a plain literal, is read; anything else (or a value from the env) is a reason to be unsure. */
export function frontendArg(arg: string): string | null {
  const eq = arg.indexOf('=');
  if ((eq < 0 ? arg : arg.slice(0, eq)).trim() !== 'BUILDKIT_SYNTAX') return null;
  const v = eq < 0 ? null : arg.slice(eq + 1).trim().replace(/^(["'])(.*)\1$/, '$2');
  return v !== null && OFFICIAL_FRONTEND.test(v) ? null : 'a BUILDKIT_SYNTAX build arg that picks a custom Dockerfile frontend';
}
/**
 * `docker build` / `docker buildx build` words from index `from` to `end` (exclusive): the Dockerfile named by -f/--file
 * (relative to the folder the command runs in), the one context word, and --target. Null for a `--check` / `--call` run
 * (a lint of the Dockerfile, not a build). P57 (M1, M3): `{ unsure }` for a flag pipegen doesn't know (`--opt
 * source=…` included), no or several context words, a context that isn't a plain path (a URL, `-` for stdin, a
 * variable), a Dockerfile from stdin or a variable, and a BUILDKIT_SYNTAX build arg other than Docker's own frontend:
 * it builds, but pipegen can't tell what.
 */
export function buildWords(at: At, from: number, end: number): BuildWords | { unsure: string } | null {
  let unsure: string | null = null;
  let file: string | null = null;
  let target: string | null = null;
  const positional: string[] = [];
  let rest = false;
  for (let i = from; i < end; i++) {
    const w = at(i);
    if (w === null) return null;
    if (rest || !w.startsWith('-') || w === '-') {
      positional.push(w);
      continue;
    }
    if (w === '--') {
      rest = true;
      continue;
    }
    const eq = w.indexOf('=');
    const name = eq < 0 ? w : w.slice(0, eq);
    if (name === '--check' || name === '--call') return null;
    if (BUILD_VALUE.has(name)) {
      const value = eq < 0 ? at(++i) : w.slice(eq + 1);
      if (value === null) return { unsure: 'a build command line pipegen can\'t read to its end' };
      if (name === '-f' || name === '--file') file = value;
      else if (name === '--target') target = value;
      else if (name === '--build-arg') unsure ??= frontendArg(value);
    } else if (!(eq < 0 && BUILD_BOOL.has(name))) unsure ??= `a build flag pipegen doesn't read (${name.slice(0, 40)})`;
  }
  if (unsure !== null) return { unsure };
  const context = positional.length === 1 ? plainPath(positional[0]) : null;
  if (context === null) return { unsure: "a build context pipegen can't place" };
  if (file !== null && plainPath(file) === null) return { unsure: "a Dockerfile path pipegen can't place" };
  if (target !== null && !/^[A-Za-z0-9_.-]{1,64}$/.test(target)) return { unsure: "a build target pipegen can't read" };
  return { file, context, target };
}

// ---------- docker compose ----------

const COMPOSE_GLOBAL_VALUE: ReadonlySet<string> = new Set(['-f', '--file', '-p', '--project-name', '--profile', '--env-file', '--ansi', '--progress', '--parallel']);
const COMPOSE_GLOBAL_BOOL: ReadonlySet<string> = new Set(['--compatibility', '--verbose', '--all-resources']);
const SERVICE_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

export interface ComposeWords {
  /** The compose files named by -f/--file, in order (plain relative paths); null = none named (the default files). */
  files: string[] | null;
  /** P57 (C3): the profiles `--profile` turns on (literal names, `*` for all). */
  profiles: string[];
  /**
   * P57 (C3): why pipegen can't tell which compose files or services this command uses (an --env-file, a -f it can't
   * place, --project-directory, a global flag it doesn't know), or null. The command is still what it is (a build, a run),
   * but what runs inside it is unknown, never covered and never missing.
   */
  unsure: string | null;
  /** The subcommand word (build, run, exec, up, …) and its index, or null when the line ends or a flag isn't known. */
  sub: string | null;
  subAt: number;
}
/**
 * The global flags of `docker compose` / `docker-compose` from index `from`, up to the subcommand. Null for `--dry-run`
 * (nothing runs) or a line that ends early. P57 (C3): an `--env-file` (it may set COMPOSE_FILE or COMPOSE_PROFILES), a
 * `-f` that isn't a plain relative path, `--project-directory` (it moves where paths are read from) and a flag pipegen
 * doesn't know give `unsure`: the subcommand is still read, what runs inside it is unknown. A global flag pipegen
 * doesn't know may take the next word as its value, so the subcommand is looked for past it only when that word is
 * one compose knows.
 */
const COMPOSE_SUBCOMMANDS: ReadonlySet<string> = new Set(['build', 'run', 'exec', 'up']);
export function composeWords(at: At, from: number, end: number): ComposeWords | null {
  const files: string[] = [];
  const profiles: string[] = [];
  let unsure: string | null = null;
  let i = from;
  for (; i < end; i++) {
    const w = at(i);
    if (w === null) return null;
    if (!w.startsWith('-') || w === '-') {
      if (unsure !== null && !COMPOSE_SUBCOMMANDS.has(w) && i + 1 < end) continue; // the value of a flag pipegen doesn't know
      break;
    }
    const eq = w.indexOf('=');
    const name = eq < 0 ? w : w.slice(0, eq);
    if (name === '--dry-run') return null;
    if (COMPOSE_GLOBAL_VALUE.has(name)) {
      const value = eq < 0 ? at(++i) : w.slice(eq + 1);
      if (value === null) return null;
      if (name === '-f' || name === '--file') {
        const p = plainPath(value);
        if (p === null) unsure ??= "a compose file named by a variable or a path pipegen can't place";
        else files.push(p);
      } else if (name === '--env-file') unsure ??= "an --env-file pipegen doesn't read (it may set COMPOSE_FILE or COMPOSE_PROFILES)";
      else if (name === '--profile') {
        if (/^[A-Za-z0-9_.*-]{1,64}$/.test(value)) profiles.push(value);
        else unsure ??= "a profile pipegen can't read";
      }
    } else if (name === '--project-directory') {
      if (eq < 0) i++;
      unsure ??= 'a --project-directory, which moves where compose reads its files';
    } else if (!(eq < 0 && COMPOSE_GLOBAL_BOOL.has(name))) unsure ??= "a compose flag pipegen doesn't know";
  }
  return { files: files.length === 0 ? null : files, profiles, unsure, sub: i < end ? at(i) : null, subAt: i };
}

/** `docker compose build [flags] [service…]`: the service names, or null (unknown flag, `--dry-run`, a word that isn't a service). */
const COMPOSE_BUILD_VALUE: ReadonlySet<string> = new Set(['--build-arg', '--builder', '-m', '--memory', '--ssh', '--progress']);
const COMPOSE_BUILD_BOOL: ReadonlySet<string> = new Set(['--no-cache', '--pull', '--push', '-q', '--quiet', '--with-dependencies']);
export function composeBuildServices(at: At, from: number, end: number): string[] | null {
  const out: string[] = [];
  for (let i = from; i < end; i++) {
    const w = at(i);
    if (w === null) return null;
    if (w.startsWith('-')) {
      const eq = w.indexOf('=');
      const name = eq < 0 ? w : w.slice(0, eq);
      if (COMPOSE_BUILD_VALUE.has(name)) {
        if (eq < 0 && at(++i) === null) return null;
      } else if (!(eq < 0 && COMPOSE_BUILD_BOOL.has(name))) return null;
    } else if (SERVICE_RE.test(w)) out.push(w);
    else return null;
  }
  return out;
}

/**
 * `docker compose run|exec [flags] <service> <command…>`: the service name and the index of the command's first word.
 * Flags that don't change what runs or where are skipped; `--entrypoint` and `-w/--workdir` (another command, another
 * folder), `--build` and any flag pipegen doesn't know give null. P57 (C2): so does `-d`/`--detach`: the command runs in
 * the background and compose returns at once, so its failure never reaches the step.
 */
const RUN_VALUE: ReadonlySet<string> = new Set(['-e', '--env', '-v', '--volume', '-p', '--publish', '-u', '--user', '--name', '-l', '--label', '--cap-add', '--cap-drop', '--pull', '--env-from-file', '--index']);
const RUN_BOOL: ReadonlySet<string> = new Set([
  '--rm', '-T', '--no-TTY', '--no-tty', '-i', '-t', '--interactive', '--tty', '--no-deps', '--service-ports', '-P', '--use-aliases', '--quiet-pull', '--remove-orphans',
  '--privileged', '--quiet',
]);
export function composeRunWords(at: At, from: number, end: number): { service: string; commandAt: number } | null {
  for (let i = from; i < end; i++) {
    const w = at(i);
    if (w === null) return null;
    if (!w.startsWith('-')) return SERVICE_RE.test(w) && i + 1 < end ? { service: w, commandAt: i + 1 } : null;
    const eq = w.indexOf('=');
    const name = eq < 0 ? w : w.slice(0, eq);
    if (RUN_VALUE.has(name)) {
      if (eq < 0 && at(++i) === null) return null;
    } else if (!(eq < 0 && RUN_BOOL.has(name))) return null;
  }
  return null;
}
