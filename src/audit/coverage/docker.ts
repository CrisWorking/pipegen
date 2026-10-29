// Coverage mapper (see ../coverage.ts for the rules): the RUN lines of Dockerfiles that CI builds, and compose services (P55, batch B).
//
// A test, lint or type check inside `RUN` in a Dockerfile fails the image build when it fails, so when CI builds that
// Dockerfile (`docker build`, docker/build-push-action, `docker compose build`) it is a check that runs in CI, under the
// same rules as any other shell text: each RUN is its own `/bin/sh -c` (no -e, so only its last list fails it), a RUN
// under a condition or with `|| true` is partial, and a command pipegen can't place is unknown. What the Dockerfile
// builds is read the way BuildKit builds it:
//   - only the stages the final stage (or `--target`) needs are built: that stage, the stage its FROM names, and the
//     stages its COPY --from= and RUN --mount from= name, transitively; a `test` stage nothing needs never runs;
//   - the folder a RUN works in comes from WORKDIR and the COPY lines that put repo folders into the image, so
//     `bun run build` in /app/frontend reads frontend/package.json;
//   - a Dockerfile pipegen can't read the way the builder does (a heredoc, a `# escape=` directive, a SHELL, a missing or
//     unreadable file) is unknown for every script check, never covered and never missing.
// `docker compose run|exec <service> <command>` counts in the service's build context. Files are read through the script
// reader (no symbolic link at any level, inside the repo, the read limits) and are counted with the script files
// (MAX_SCRIPT_FILES); the work per Dockerfile is bounded.
import { posix } from 'node:path';
import { regexSafe } from '../../read/limits.js';
import { MAX_SCRIPT_FILES } from './bounds.js';
import { resolveDir } from './helpers.js';
import { UNKNOWN_PREFIX, gateOf, gated } from './settings.js';
import { SCRIPT_CATEGORIES, UNKNOWN_SCRIPT_CATEGORIES, scanShell, type ShellMode } from './shell.js';
import { asObj } from '../../read/manifest.js';
import { OFFICIAL_FRONTEND, frontendArg } from './docker-words.js';
import type { Ctx, DockerBuild, Found, Obj, Reason } from './types.js';

const MAX_DOCKERFILE_LINES = 5_000;
const MAX_STAGES = 50;
const MAX_RUNS = 300;
const MAX_COMPOSE_SERVICES = 200;
/** A RUN is `/bin/sh -c`: no -e, no pipefail (https://docs.docker.com/reference/dockerfile/#run). */
const RUN_SHELL: ShellMode = { errexit: false, pipefail: false };

/** What `resolveScripts` needs from this module without importing it back (the mapper has no import cycle). */
type Resolve = (ctx: Ctx, found: Found[]) => Promise<Found[]>;

// ---------- compose files ----------

interface ComposeService {
  context: string | null; file: string | null; target: string | null; hasBuild: boolean; profiles: readonly string[]; environment: DockerEnv;
  /** P57 (M3): its build `args:` may pick a custom Dockerfile frontend (BUILDKIT_SYNTAX), or can't be read: why, else null. */
  frontend: string | null;
  /** P60 (R1): its `env_file:` files (repo paths; `required: false` ones may be missing), or 'unsure' when pipegen can't place one. */
  envFiles: readonly { rel: string; required: boolean }[] | 'unsure';
}
/** The services, or: no compose file ('missing'), one pipegen couldn't read ('unreadable'), or a set it can't be sure of (`why`, P57 C3). */
export type ComposeModel = ReadonlyMap<string, ComposeService> | 'unreadable' | 'missing' | { why: string };
/** P57 (C3): the variables that pick other compose files or services (https://docs.docker.com/compose/how-tos/environment-variables/envvars/). */
export const COMPOSE_ENV: readonly string[] = ['COMPOSE_FILE', 'COMPOSE_PROFILES', 'COMPOSE_PATH_SEPARATOR'];
const COMPOSE_ENV_LINE = /^\s*(?:export\s+)?(?:COMPOSE_FILE|COMPOSE_PROFILES|COMPOSE_PATH_SEPARATOR)\s*=/m;
/** P57 (C3): whether a service runs with these profiles on: no profile of its own, named on the command line, or one of its profiles on (`*`: all). */
/** The `why` of a compose model pipegen can't be sure of, else null. */
const unsureModel = (m: ComposeModel): string | null => (typeof m === 'object' && 'why' in m ? m.why : null);
const active = (svc: ComposeService, name: string, on: readonly string[], named: readonly string[] | null): boolean =>
  svc.profiles.length === 0 || (named?.includes(name) ?? false) || on.includes('*') || svc.profiles.some((p) => on.includes(p));
const COMPOSE_FAMILIES: readonly (readonly [string, string])[] = [
  ['compose.yaml', 'compose.override.yaml'], ['compose.yml', 'compose.override.yml'], ['docker-compose.yaml', 'docker-compose.override.yaml'], ['docker-compose.yml', 'docker-compose.override.yml'],
];

/** Counts one file against the script-file bound; false past it. */
function spend(ctx: Ctx): boolean {
  if (ctx.scriptFileReads >= MAX_SCRIPT_FILES) return false;
  ctx.scriptFileReads++;
  return true;
}

/**
 * The services of the compose files `files` (null: the default file of `cwd`, and its override) with the folder and
 * Dockerfile each builds. A later file's `build` keys replace an earlier one's. Paths are relative to the first file's
 * folder; a context that is a URL, absolute or holds a variable has no folder (null).
 */
async function composeModel(ctx: Ctx, files: readonly string[] | null, cwd: string): Promise<ComposeModel> {
  const key = `${cwd}\u0000${(files ?? []).join('\u0001')}`;
  const known = ctx.composeMemo.get(key);
  if (known !== undefined) return known;
  const model = await (async (): Promise<ComposeModel> => {
    const docs: { dir: string; doc: Obj }[] = [];
    const candidates = files !== null ? files.map((f) => resolveDir(cwd, f)) : null;
    const tryRead = async (rel: string | null): Promise<'missing' | 'unreadable' | Obj> => {
      if (rel === null) return 'unreadable';
      if (!spend(ctx)) return 'unreadable';
      const r = await ctx.scriptRead.yaml(rel);
      return 'ok' in r ? r.ok : r.fail === 'missing' ? 'missing' : 'unreadable';
    };
    // P57 (C3): a .env in the folder compose runs in (or the first file's) that sets COMPOSE_FILE or COMPOSE_PROFILES picks
    // other files or services; one pipegen can't read might
    const envFolders = new Set([cwd, ...(candidates?.[0] === null || candidates === null ? [] : [posix.dirname(candidates[0] as string) || '.'])]);
    for (const folder of envFolders) {
      const rel = resolveDir(folder, '.env');
      if (rel === null || !spend(ctx)) return { why: "a .env file pipegen couldn't check" };
      const env = await ctx.scriptRead.text(rel);
      if ('fail' in env && env.fail !== 'missing') return { why: "a .env file pipegen couldn't read (it may set COMPOSE_FILE or COMPOSE_PROFILES)" };
      if ('ok' in env && COMPOSE_ENV_LINE.test(env.ok)) return { why: 'a .env file that sets COMPOSE_FILE or COMPOSE_PROFILES' };
    }
    if (candidates !== null) {
      for (const rel of candidates) {
        const d = await tryRead(rel);
        if (typeof d === 'string') return d;
        docs.push({ dir: posix.dirname(rel as string), doc: d });
      }
    } else {
      for (const [base, override] of COMPOSE_FAMILIES) {
        const rel = resolveDir(cwd, base);
        const d = await tryRead(rel);
        if (d === 'missing') continue;
        if (typeof d === 'string') return d;
        docs.push({ dir: posix.dirname(rel as string), doc: d });
        const o = await tryRead(resolveDir(cwd, override));
        if (o !== 'missing') {
          if (typeof o === 'string') return o;
          docs.push({ dir: docs[0]!.dir, doc: o });
        }
        break;
      }
      if (docs.length === 0) return 'missing';
    }
    const baseDir = docs[0]!.dir === '' ? '.' : docs[0]!.dir;
    const out = new Map<string, ComposeService>();
    for (const { doc } of docs) {
      // P57 (C3): other files pipegen doesn't follow can add or change services
      if ('include' in doc) return { why: 'a compose file with an include: pipegen doesn\'t follow' };
      const all = Object.entries(asObj(doc.services));
      // P57 (fail closed): more services than pipegen reads: it can't tell which are built
      if (all.length > MAX_COMPOSE_SERVICES) return { why: 'a compose file with more services than pipegen reads' };
      for (const [name, raw] of all) {
        const svc = asObj(raw);
        const prev = out.get(name);
        if ('extends' in svc) return { why: `a compose service (${name}) that extends another, which pipegen doesn't follow` };
        // a later file's profiles replace an earlier one's; a value pipegen can't read leaves the set unknown
        const profiles = !('profiles' in svc) ? (prev?.profiles ?? []) : Array.isArray(svc.profiles) && svc.profiles.every((x) => typeof x === 'string') ? svc.profiles as string[] : null;
        if (profiles === null) return { why: `a compose service (${name}) whose profiles pipegen can't read` };
        // P57 (C5): the service's environment (a map or a list of NAME=value) reaches what runs in it; a later file's adds to it
        const environment = { ...(prev?.environment ?? {}), ...composeEnvironment(svc.environment) };
        // P60 (R1): a later file's env_file list is added to the earlier one's (Compose merges them); unsure in either is unsure
        const own = 'env_file' in svc ? envFilesOf(svc.env_file, baseDir) : [];
        const before = prev?.envFiles ?? [];
        const envFiles = own === 'unsure' || before === 'unsure' ? 'unsure' as const : [...before, ...own];
        if (!('build' in svc) || svc.build === null || svc.build === undefined) {
          if (prev === undefined) out.set(name, { context: null, file: null, target: null, hasBuild: false, profiles, environment, frontend: null, envFiles });
          else out.set(name, { ...prev, profiles, environment, envFiles });
          continue;
        }
        const b = typeof svc.build === 'string' ? { context: svc.build } : asObj(svc.build);
        const ctxWord = typeof b.context === 'string' ? b.context : prev?.hasBuild === true ? undefined : '.';
        const folder = ctxWord === undefined ? (prev?.context ?? null) : plainContext(baseDir, ctxWord);
        const dockerfile = typeof b.dockerfile === 'string' ? b.dockerfile : undefined;
        const inline = 'dockerfile_inline' in b;
        const file = inline || folder === null ? null
          : dockerfile === undefined ? (typeof b.context === 'string' || prev?.file === null || prev === undefined ? resolveDir(folder, 'Dockerfile') : prev.file)
            : /[$\\]|^\//.test(dockerfile) ? null : resolveDir(folder, dockerfile);
        const target = typeof b.target === 'string' ? (/^[A-Za-z0-9_.-]{1,64}$/.test(b.target) ? b.target : '?') : (prev?.target ?? null);
        out.set(name, { context: folder, file, target, hasBuild: true, profiles, environment, frontend: composeFrontend(b.args) ?? prev?.frontend ?? null, envFiles });
      }
    }
    return out;
  })();
  ctx.composeMemo.set(key, model);
  return model;
}

/**
 * P60 (R1): a compose `env_file:` (a path, a list of paths, or of `{ path, required }`) as repo paths from the compose
 * file's folder; 'unsure' for a value pipegen can't place (a variable, an absolute path, `..` out of the repo, another shape).
 */
function envFilesOf(v: unknown, baseDir: string): readonly { rel: string; required: boolean }[] | 'unsure' {
  if (v === null || v === undefined) return [];
  const items = Array.isArray(v) ? v : [v];
  const out: { rel: string; required: boolean }[] = [];
  for (const it of items) {
    const o = typeof it === 'string' ? { path: it, required: true } : asObj(it);
    const path = o.path;
    if (typeof path !== 'string' || /[$\\]|^\//.test(path) || !regexSafe(path)) return 'unsure';
    const rel = resolveDir(baseDir, path);
    if (rel === null) return 'unsure';
    out.push({ rel, required: o.required !== false });
  }
  return out;
}
/** P60 (R1): the variables an env file sets (`NAME=value`, `export NAME=value`, `NAME`); null when a line can't be read that way. */
function envFileNames(text: string): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const l = line.trim();
    if (l === '' || l.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:=(.*))?$/.exec(l);
    if (m === null) return null;
    // a bare NAME passes the variable through from the environment: its value can't be read
    const v = m[2] === undefined ? '$' : m[2].trim().replace(/^(["'])(.*)\1$/, '$2');
    out[m[1] as string] = /^[A-Za-z0-9_.,:\/ -]*$/.test(v) ? v : '$';
  }
  return out;
}

/** P57 (C5): a compose `environment:` (a map, or a list of NAME=value / NAME) as names and values ('$' when not a plain literal). */
function composeEnvironment(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  const literal = (x: unknown) => (typeof x === 'string' && /^[A-Za-z0-9_.,:\/ -]*$/.test(x) ? x : typeof x === 'number' || typeof x === 'boolean' ? String(x) : '$');
  if (Array.isArray(v)) {
    for (const e of v) { // every entry (the file is bounded by the read limits): a variable past a cap could hide
      if (typeof e !== 'string') continue;
      const eq = e.indexOf('=');
      out[eq < 0 ? e : e.slice(0, eq)] = eq < 0 ? '$' : literal(e.slice(eq + 1));
    }
  } else for (const [k, x] of Object.entries(asObj(v))) out[k] = x === null ? '$' : literal(x);
  return out;
}

/** P57 (M3): compose build `args:` (a map, or a list of NAME=value / NAME) that set BUILDKIT_SYNTAX to anything but Docker's own frontend. */
function composeFrontend(args: unknown): string | null {
  if (args === undefined || args === null) return null;
  if (Array.isArray(args)) {
    for (const a of args) {
      const why = typeof a === 'string' ? frontendArg(a) : 'build args pipegen can\'t read';
      if (why !== null) return why;
    }
    return null;
  }
  if (typeof args !== 'object') return 'build args pipegen can\'t read';
  for (const [k, v] of Object.entries(asObj(args))) {
    const why = frontendArg(v === null || v === undefined ? k : `${k}=${typeof v === 'string' ? v : '$'}`);
    if (why !== null) return why;
  }
  return null;
}

/** A compose build context word as a repo folder: not a URL, an absolute path or a variable. */
function plainContext(baseDir: string, word: string): string | null {
  if (!regexSafe(word) || /[$\\]|^\/|^[A-Za-z][A-Za-z0-9+.-]*:/.test(word)) return null;
  return resolveDir(baseDir, word);
}

/**
 * `docker compose run|exec <service> <command>` (Found.composeRun): the command runs in the service's container, so it
 * counts for the folder the service builds from. A service without a `build:` (an image), an unreadable or missing compose
 * file, or a context pipegen can't place is unknown for every script check, never missing.
 */
export async function placeComposeRun(ctx: Ctx, f: Found): Promise<Found | null> {
  const run = f.composeRun;
  if (run === undefined) return f;
  const model = run.unsure !== null ? { why: run.unsure } : await composeModel(ctx, run.files, run.cwd);
  if (model === 'missing') return null; // the runner fails: nothing runs
  const unsure = unsureModel(model);
  const svc = typeof model === 'string' || unsure !== null ? undefined : (model as ReadonlyMap<string, ComposeService>).get(run.service);
  if (svc === undefined || !svc.hasBuild || svc.context === null) {
    const why = model === 'unreadable' ? "a compose file pipegen couldn't read" : unsure !== null ? `a compose setup pipegen can't be sure of (${unsure})`
      : svc === undefined ? `a service (${run.service}) that isn't in the compose file`
        : !svc.hasBuild ? `a service (${run.service}) that uses a ready-made image` : "a service whose build folder pipegen can't place";
    return { categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: `${f.subject} runs in ${why}, so pipegen can't tell which service it checks.` };
  }
  // the command runs in the image's last WORKDIR (the folder COPY put there): the host folder it maps to, else the build folder
  let dir = svc.context;
  let imageEnv: DockerEnv = {};
  if (svc.file !== null && svc.target !== '?') {
    const d = await loadDockerfile(ctx, svc.file, svc.context);
    if ('parsed' in d && 'stages' in d.parsed) {
      const needed = neededStages(d.parsed.stages, svc.target);
      const last = needed === null ? null : Math.max(...needed);
      const end = last === null ? null : d.parsed.stages[last]?.endDir ?? null;
      if (end !== null) dir = end;
      if (last !== null) imageEnv = d.parsed.stages[last]?.endEnv ?? {};
    }
  }
  const { composeRun: _placed, ...rest } = f;
  void _placed;
  // P60 (R1): the service's env_file: files, read like its environment:; one pipegen can't read could set anything
  let fileEnv: Record<string, string> | null = {};
  if (svc.envFiles === 'unsure') fileEnv = null;
  else {
    for (const ef of svc.envFiles) {
      if (!spend(ctx)) {
        fileEnv = null;
        break;
      }
      const t = await ctx.scriptRead.text(ef.rel);
      if ('fail' in t && t.fail === 'missing' && !ef.required) continue;
      const names = 'ok' in t ? envFileNames(t.ok) : null;
      if (names === null) {
        fileEnv = null;
        break;
      }
      fileEnv = { ...fileEnv, ...names };
    }
  }
  // an env_file pipegen couldn't place or read could set anything: unknown, with its own reason (re-review 2, n1)
  if (fileEnv === null) {
    return { categories: rest.categories.map((c) => (c.startsWith(UNKNOWN_PREFIX) ? c : `${UNKNOWN_PREFIX}${c}`)), by: rest.by, subject: rest.subject, dir: null, reason: null,
      partialWhy: `${rest.subject} runs through docker compose with an env_file pipegen couldn't place or read, and that file could set a variable that changes what runs, so pipegen can't tell what it checks.` };
  }
  // P57 (C5): the image's ENV and the service's environment: reach the command like a step's env: (an env given as a
  // plain string is "could be anything" to gateOf)
  const [placed] = gated([{ ...rest, dir, compose: true }], gateOf([], envsOf({ ...imageEnv, ...fileEnv, ...svc.environment }), undefined, ctx.sigs.softEnv, ctx.sigs.configFiles));
  return placed ?? null;
}

// ---------- Dockerfiles ----------

/** P57 (C5): the ENV and ARG names a RUN sees (inherited through FROM), with their literal value ('$' when pipegen can't read it). */
export type DockerEnv = Readonly<Record<string, string>>;
export interface Run { text: string; dir: string | null; env: DockerEnv }
export interface Stage { name: string | null; needs: string[]; runs: Run[]; endDir: string | null; endEnv: DockerEnv }
export type Parsed = { stages: Stage[] } | { unreadable: string };

/**
 * P57 (C5): the names an ENV or ARG line sets, with their value when it is a plain literal ('$' otherwise): `ENV K=v K2="v"`,
 * the old `ENV K v`, `ARG K[=default] …` (an ARG without a default takes its value from a --build-arg, so '$').
 */
function envWords(op: 'ENV' | 'ARG', rest: string): Record<string, string> {
  const out: Record<string, string> = {};
  const plain = (v: string) => (/^"[A-Za-z0-9_.,:\/ -]*"$|^'[A-Za-z0-9_.,:\/ -]*'$/.test(v) ? v.slice(1, -1) : /^[A-Za-z0-9_.,:\/-]*$/.test(v) ? v : '$');
  // P60 (m1): BuildKit expands and unquotes keys too, so a key that isn't a plain name could be any variable: unsure
  const unsure = () => ({ ...out, [UNSURE_ENV]: '$' });
  const t = rest.trim();
  const words = t.match(/(?:"[^"]*"|'[^']*'|[^\s"']+)+/g) ?? [];
  if (op === 'ENV' && !(words[0] ?? '').includes('=')) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s+(.*)$/.exec(t);
    if (m === null) return unsure();
    out[m[1] as string] = plain((m[2] as string).trim());
    return out;
  }
  for (const w of words) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$/.exec(w);
    if (m === null || (op === 'ENV' && m[2] === undefined)) return unsure();
    out[m[1] as string] = m[2] === undefined ? '$' : plain(m[2]);
  }
  return out;
}
/** P60 (m1): the key an ENV or ARG line with a name pipegen can't read adds: the env gate is then all on. */
export const UNSURE_ENV = '\u0000';
/** The env objects for gateOf: a plain string ("could be anything") joins an env that holds UNSURE_ENV. */
const envsOf = (env: DockerEnv): unknown[] => (UNSURE_ENV in env ? [env, '$'] : [env]);

/** The words of a COPY/ADD or FROM line, past its `--flag` words, as [flags, words]. */
function wordsOf(rest: string): { flags: string[]; words: string[] } {
  const all = rest.replace(/[[\],"]/g, ' ').split(/\s+/).filter((w) => w !== '');
  return { flags: all.filter((w) => w.startsWith('--')), words: all.filter((w) => !w.startsWith('--')) };
}
const flagValue = (flags: readonly string[], name: string): string | undefined => flags.find((x) => x.toLowerCase().startsWith(`--${name}=`))?.slice(name.length + 3);

/**
 * A Dockerfile read the way BuildKit builds it (see the header): its stages, each with the stages it needs and its RUN
 * texts with the repo folder each works in. `context` is the build context (a repo folder).
 */
async function parseDockerfile(ctx: Ctx, text: string, context: string): Promise<Parsed> {
  const raw = text.split(/\r?\n/);
  if (raw.length > MAX_DOCKERFILE_LINES || !raw.every(regexSafe)) return { unreadable: 'it has more or longer lines than pipegen reads' };
  // P57 (M3, fail closed): the whole leading directive block is read (the file is already bounded): an escape directive
  // changes how lines join, a syntax directive picks the frontend that reads the file
  const directive = leadingDirective(text);
  if (directive === 'escape') return { unreadable: 'it changes the escape character' };
  if (directive === 'frontend') return { unreadable: 'it picks its own Dockerfile frontend (a syntax directive)' };
  // instructions, with line continuations joined (comment lines inside a continuation are dropped, as Docker does)
  const lines: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    let line = (raw[i] as string).trim();
    if (line === '' || line.startsWith('#')) continue;
    while (line.endsWith('\\') && i + 1 < raw.length) {
      line = line.slice(0, -1).trimEnd();
      let next = (raw[++i] as string).trim();
      while ((next === '' || next.startsWith('#')) && i + 1 < raw.length) next = (raw[++i] as string).trim();
      line = `${line} ${next}`;
    }
    lines.push(line);
  }
  const stages: Stage[] = [];
  const names = new Map<string, number>();
  interface State { workdir: string | null; maps: { dest: string; host: string }[]; env: Record<string, string> }
  const states: State[] = [];
  let cur: Stage | null = null;
  let state: State = { workdir: '/', maps: [], env: {} };
  let runs = 0;
  const refOf = (ref: string): number | null => {
    const lower = ref.toLowerCase();
    if (names.has(lower)) return names.get(lower) as number;
    return /^\d{1,2}$/.test(ref) && Number(ref) < stages.length ? Number(ref) : null;
  };
  const hostOf = (workdir: string | null, st: State = state): string | null => {
    if (workdir === null) return null;
    let best: { dest: string; host: string } | null = null;
    for (const m of st.maps) if ((workdir === m.dest || workdir.startsWith(`${m.dest === '/' ? '' : m.dest}/`)) && (best === null || m.dest.length >= best.dest.length)) best = m;
    return best === null ? null : resolveDir(best.host, posix.relative(best.dest, workdir) || '.');
  };
  const abs = (p: string): string | null => (/[$\\]/.test(p) || state.workdir === null && !p.startsWith('/') ? null : posix.normalize(p.startsWith('/') ? p : posix.join(state.workdir as string, p)).replace(/(.)\/+$/, '$1'));
  for (const line of lines) {
    const m = /^([A-Za-z]+)\s+(.*)$/.exec(line);
    if (m === null) continue;
    const op = (m[1] as string).toUpperCase();
    const rest = m[2] as string;
    if ((op === 'RUN' || op === 'COPY' || op === 'ADD') && /<<-?\s*["']?[A-Za-z_]/.test(rest)) return { unreadable: 'it uses a here-document' };
    if (op === 'FROM') {
      if (stages.length >= MAX_STAGES) return { unreadable: 'it has more stages than pipegen reads' };
      const { flags, words } = wordsOf(rest);
      void flags;
      const asAt = words.findIndex((w) => w.toLowerCase() === 'as');
      const name = asAt >= 0 && /^[A-Za-z0-9_.-]{1,64}$/.test(words[asAt + 1] ?? '') ? (words[asAt + 1] as string) : null;
      const parent = /\$/.test(words[0] ?? '') ? null : refOf(words[0] ?? '');
      cur = { name, needs: parent === null ? [] : [String(parent)], runs: [], endDir: null, endEnv: {} };
      state = parent === null ? { workdir: '/', maps: [], env: {} } : { workdir: states[parent]!.workdir, maps: [...states[parent]!.maps], env: { ...states[parent]!.env } };
      if (name !== null) names.set(name.toLowerCase(), stages.length);
      stages.push(cur);
      states.push(state);
      continue;
    }
    if (cur === null) continue; // ARG before the first FROM
    if (op === 'SHELL') return { unreadable: 'it changes the shell RUN uses' };
    // P57 (C5): ENV and ARG set variables every later RUN of the stage (and of the stages built FROM it) sees
    if (op === 'ENV' || op === 'ARG') {
      for (const [k, v] of Object.entries(envWords(op, rest))) state.env[k] = v;
      continue;
    }
    if (op === 'WORKDIR') {
      state.workdir = abs(rest.replace(/^["']|["']$/g, '').trim());
      continue;
    }
    if (op === 'COPY' || op === 'ADD') {
      const { flags, words } = wordsOf(rest);
      const from = flagValue(flags, 'from');
      if (from !== undefined) {
        const at = refOf(from);
        if (at !== null && !cur.needs.includes(String(at))) cur.needs.push(String(at));
        continue;
      }
      const dest = words.length >= 2 ? abs(words[words.length - 1] as string) : null;
      const sources = words.slice(0, -1);
      if (dest === null) continue;
      const destIsDir = (words[words.length - 1] as string).endsWith('/');
      // each plain source as a host path and its kind; any glob, variable, URL or absolute source leaves the copy unmapped
      const plain = sources.filter((src) => !/[*?$]|^[a-z][a-z0-9+.-]*:\/\//i.test(src) && !src.startsWith('/'));
      if (plain.length === sources.length && (sources.length === 1 || destIsDir)) {
        const hosts = sources.map((src) => resolveDir(context, src.replace(/\/+$/, '') || '.'));
        const kinds = await Promise.all(hosts.map((h) => (h === null ? Promise.resolve(null) : ctx.scriptRead.kind(h))));
        if (sources.length === 1 && kinds[0] === 'dir') state.maps.push({ dest, host: hosts[0] as string });
        else if (destIsDir && kinds.every((k) => k === 'file')) {
          // files copied into a folder keep their names: that folder holds them, so it maps to their folder when they share one
          const dirs = new Set(hosts.map((h) => posix.dirname(h as string)));
          if (dirs.size === 1) state.maps.push({ dest, host: [...dirs][0] as string });
        }
      }
      continue;
    }
    if (op === 'RUN') {
      if (++runs > MAX_RUNS) return { unreadable: 'it has more RUN lines than pipegen reads' };
      const { flags, rest: runRest } = leadingFlags(rest);
      // P57 (fail closed): more flags than pipegen reads could hide a --mount from= another stage
      if (/^--[A-Za-z]/.test(runRest)) return { unreadable: 'a RUN line has more flags than pipegen reads' };
      for (const f of flags) {
        const mount = /^--mount=(.*)$/i.exec(f);
        const from = mount === null ? undefined : /(?:^|,)from=([^,]+)/.exec(mount[1] as string)?.[1];
        const at = from === undefined ? null : refOf(from);
        if (at !== null && !cur.needs.includes(String(at))) cur.needs.push(String(at));
      }
      const text = runText(leadingFlags(rest).rest);
      if (text !== null) cur.runs.push({ text, dir: hostOf(state.workdir), env: { ...state.env } });
    }
  }
  for (const [i, stage] of stages.entries()) {
    stage.endDir = hostOf(states[i]!.workdir, states[i]!);
    stage.endEnv = { ...states[i]!.env };
  }
  return { stages };
}

/**
 * P57 (M3): whether the Dockerfile picks a frontend other than Docker's own, the way BuildKit detects one: a `syntax`
 * directive in the leading comment block, as `# syntax=x` or `// syntax=x` (any letter case, spaces around `=`, after
 * other directives such as `# escape=` or `# check=`), or a JSON file with a `syntax` key. Fail closed: a leading
 * comment that mentions syntax but doesn't read as a directive counts too; the block ends at the first other line.
 */
function leadingDirective(text: string): 'escape' | 'frontend' | null {
  const t = text.replace(/^\ufeff/, '');
  if (t.trimStart().startsWith('{')) {
    try {
      const j = JSON.parse(t) as unknown;
      if (j !== null && typeof j === 'object' && Object.keys(j).some((k) => k.toLowerCase() === 'syntax')) return 'frontend';
    } catch { /* not JSON: read as a Dockerfile */ }
  }
  for (const line of t.split(/\r?\n/)) { // no cap: the caller already bounds the file's lines
    const l = line.trim();
    if (l === '') continue;
    if (!(l.startsWith('#') || l.startsWith('//'))) break;
    const m = /^(?:#|\/\/)\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$/.exec(l);
    if (m === null) {
      if (/syntax|escape/i.test(l)) return 'frontend';
      break;
    }
    const key = (m[1] as string).toLowerCase();
    if (key === 'escape' && l.startsWith('#')) return 'escape';
    if (key === 'syntax' && !OFFICIAL_FRONTEND.test(m[2] as string)) return 'frontend';
  }
  return null;
}

/** A Dockerfile read and parsed once per (file, context): its parse, or why it couldn't be. */
export type DockerLoad = { parsed: Parsed } | { fail: 'missing' | 'unreadable' | 'limit' };
async function loadDockerfile(ctx: Ctx, file: string, context: string): Promise<DockerLoad> {
  const key = `parsed\u0000${file}\u0000${context}`;
  const known = ctx.dockerParsed.get(key);
  if (known !== undefined) return known;
  let out: DockerLoad;
  if (!spend(ctx)) out = { fail: 'limit' };
  else {
    const t = await ctx.scriptRead.text(file);
    out = 'fail' in t ? { fail: t.fail === 'missing' ? 'missing' : 'unreadable' } : { parsed: await parseDockerfile(ctx, t.ok, context) };
  }
  ctx.dockerParsed.set(key, out);
  return out;
}

/** The `--flag` words at the start of a RUN, and the rest. */
function leadingFlags(rest: string): { flags: string[]; rest: string } {
  const flags: string[] = [];
  let r = rest;
  for (let m = /^(--[A-Za-z-]+(?:=\S*)?)\s+(.*)$/.exec(r); m !== null && flags.length < 8; m = /^(--[A-Za-z-]+(?:=\S*)?)\s+(.*)$/.exec(r)) {
    flags.push(m[1] as string);
    r = m[2] as string;
  }
  return { flags, rest: r };
}
/** The shell text of a RUN: shell form as is; exec form (`["pytest", "-q"]`) as its words when they are plain. Null for text pipegen won't read. */
function runText(rest: string): string | null {
  const t = rest.trim();
  if (!regexSafe(t)) return null;
  if (!t.startsWith('[')) return t;
  try {
    const words = JSON.parse(t) as unknown;
    return Array.isArray(words) && words.length > 0 && words.every((w) => typeof w === 'string' && /^[A-Za-z0-9_./:=@+,%-]+$/.test(w)) ? (words as string[]).join(' ') : null;
  } catch {
    return null;
  }
}

/** The stages the final stage (or the target) needs, built from FROM, COPY --from and RUN --mount from=, transitively; null when the target isn't a stage. */
function neededStages(stages: readonly Stage[], target: string | null): Set<number> | null {
  const last = target === null ? stages.length - 1 : stages.findIndex((s) => s.name?.toLowerCase() === target.toLowerCase());
  if (last < 0) return null;
  const out = new Set<number>();
  const queue = [last];
  while (queue.length > 0) {
    const i = queue.pop() as number;
    if (out.has(i)) continue;
    out.add(i);
    for (const n of stages[i]!.needs) queue.push(Number(n));
  }
  return out;
}

/** The RUN texts of the Dockerfile `b` builds that count as checks, as findings under the building command `f`. */
async function dockerfileRuns(ctx: Ctx, b: DockerBuild, f: Found, outer: Reason | null, resolve: Resolve): Promise<Found[]> {
  const unknown = (why: string): Found[] => [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: f.dir, reason: null, partialWhy: why }];
  // P57 (M1, M3): a build pipegen can't read may build any Dockerfile with any frontend: unknown for every service
  if (b.unsure !== undefined) {
    return [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: `${f.subject} uses ${b.unsure}, so pipegen can't tell what the build runs.` }];
  }
  const key = `docker\u0000${b.file}\u0000${b.context}\u0000${b.target ?? ''}`;
  let runs = ctx.scriptMemo.get(key);
  if (runs === undefined) {
    ctx.scriptMemo.set(key, []); // being worked out
    const loaded = await loadDockerfile(ctx, b.file, b.context);
    if ('fail' in loaded && loaded.fail === 'limit') {
      runs = unknown(`There are more files than pipegen follows, so it can't tell what the Dockerfile ${b.file} runs.`);
    } else {
      if ('fail' in loaded) {
        runs = loaded.fail === 'missing' ? [] : unknown(`${f.subject} builds the Dockerfile ${b.file}, which pipegen couldn't read (a symbolic link, too large or outside the repo), so it can't tell what it runs.`);
      } else {
        const parsed = loaded.parsed;
        const needed = 'stages' in parsed ? neededStages(parsed.stages, b.target) : null;
        if ('unreadable' in parsed) runs = unknown(`${f.subject} builds the Dockerfile ${b.file}, and ${parsed.unreadable}, so pipegen can't tell what it runs.`);
        else if (needed === null) runs = unknown(`${f.subject} builds the stage ${b.target ?? ''} of ${b.file}, which pipegen can't find.`);
        else {
          const out: Found[] = [];
          for (const [i, stage] of parsed.stages.entries()) {
            if (!needed.has(i)) continue;
            for (const run of stage.runs) {
              const scanned = scanShell(run.text, run.dir, ctx.sigs, ctx.budget, RUN_SHELL);
              if (run.dir === null) { // a WORKDIR no COPY puts a repo folder in: a check here could be any service's
                if (scanned.some((g) => g.categories.length > 0 || g.script !== undefined || g.byName !== undefined || g.scriptFile !== undefined)) {
                  out.push({ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null,
                    partialWhy: `A RUN of the Dockerfile ${b.file} works in a folder pipegen can't place, so it can't tell which service its checks cover.` });
                }
                continue;
              }
              // P57 (C5): the ENV and ARG values the RUN sees count like a step's env:
              const inner = gated(await resolve(ctx, scanned), gateOf([run.text], envsOf(run.env), undefined, ctx.sigs.softEnv, ctx.sigs.configFiles));
              for (const g of inner) {
                const categories = g.categories.filter((x) => SCRIPT_CATEGORIES.has(x.startsWith(UNKNOWN_PREFIX) ? x.slice(UNKNOWN_PREFIX.length) : x));
                if (categories.length === 0) continue;
                const where = `in a RUN of the Dockerfile ${b.file}`;
                if (g.dir === null && categories.some((c) => !c.startsWith(UNKNOWN_PREFIX))) {
                  out.push({ categories: categories.map((c) => (c.startsWith(UNKNOWN_PREFIX) ? c : `${UNKNOWN_PREFIX}${c}`)), by: g.by, subject: `${g.subject} ${where}`, dir: null, reason: null,
                    partialWhy: `A RUN of the Dockerfile ${b.file} works in a folder pipegen can't place, so it can't tell which service ${g.subject.charAt(0).toLowerCase()}${g.subject.slice(1)} checks.` });
                } else out.push({ ...g, categories, subject: `${g.subject} ${where}`, hookRun: false });
              }
            }
          }
          runs = out;
        }
      }
    }
    ctx.scriptMemo.set(key, runs);
  }
  // the building command's own reason (an `||`, a pipe, an if) comes first, as for a script file
  return runs.map((g): Found => {
    const { partialWhy, ...rest } = g;
    return { ...rest, reason: outer ?? g.reason, ...(outer === null && partialWhy !== undefined ? { partialWhy } : {}) };
  });
}

/** The Dockerfiles a building command (`dockerBuild` or `composeBuild`) builds, and the checks their RUN lines add. */
export async function buildRuns(ctx: Ctx, f: Found, resolve: Resolve): Promise<Found[]> {
  const builds: DockerBuild[] = [];
  if (f.dockerBuild !== undefined) builds.push(f.dockerBuild);
  if (f.composeBuild !== undefined) {
    const cb = f.composeBuild;
    const model = cb.unsure !== null ? { why: cb.unsure } : await composeModel(ctx, cb.files, cb.cwd);
    if (model === 'unreadable') {
      return [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: f.dir, reason: null, partialWhy: `${f.subject} uses a compose file pipegen couldn't read, so it can't tell what the Dockerfiles run.` }];
    }
    const unsure = unsureModel(model);
    if (unsure !== null) {
      // P57 (C3): which services compose builds depends on something pipegen can't read: any service's checks may run
      return [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: `${f.subject} uses ${unsure}, so pipegen can't tell which services it builds or what their Dockerfiles run.` }];
    }
    if (model !== 'missing') {
      const services = model as ReadonlyMap<string, ComposeService>;
      // P57 (C3): with no service named, only the services whose profiles are on are built
      const names = cb.services ?? [...services.keys()].filter((n) => active(services.get(n) as ComposeService, n, cb.profiles, null));
      for (const name of names.slice(0, MAX_COMPOSE_SERVICES)) {
        const svc = services.get(name);
        if (svc === undefined || !svc.hasBuild) continue;
        if (svc.frontend !== null) {
          return [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: `${f.subject} builds a service (${name}) with ${svc.frontend}, so pipegen can't tell what it runs.` }];
        }
        if (svc.context === null || svc.file === null || svc.target === '?') {
          return [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: f.dir, reason: null, partialWhy: `${f.subject} builds a service (${name}) whose Dockerfile pipegen can't place, so it can't tell what it runs.` }];
        }
        builds.push({ file: svc.file, context: svc.context, target: svc.target });
      }
    }
  }
  const out: Found[] = [];
  // the building command's own reason (an `||`, a pipe, an if); the image build's "partial" for compose is not one
  const outer = f.composeBuild === undefined ? f.reason : f.composeBuild.shellReason;
  for (const b of builds) out.push(...(await dockerfileRuns(ctx, b, f, outer, resolve)));
  return f.composeBuild === undefined ? out : out.map((g) => ({ ...g, compose: true as const }));
}

/** P57 (C3): what pipegen says for a compose run or build when a COMPOSE_FILE / COMPOSE_PROFILES variable may be set. */
export const composeEnvWhy = (subject: string) =>
  `${subject} runs through docker compose, and a COMPOSE_FILE or COMPOSE_PROFILES variable set in this job can change which compose files and services it uses, so pipegen can't tell what it checks.`;
/**
 * P57 (C3): a step whose job may set COMPOSE_FILE, COMPOSE_PROFILES or COMPOSE_PATH_SEPARATOR (EnvGate.compose): a
 * compose run or build there is unknown for every service, whatever the default compose file says (its own services may
 * hold no tests while the file the variable names does). Applied before the commands are followed; a compose command
 * reached through a package script is caught later by its `compose` mark (settings.ts, gated).
 */
export function composeEnvGated(found: readonly Found[], compose: boolean): Found[] {
  if (!compose) return [...found];
  return found.map((f) => {
    if (f.composeRun !== undefined) return { categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: composeEnvWhy(f.subject) };
    if (f.composeBuild === undefined) return f;
    const { composeBuild: _cb, ...build } = f;
    void _cb;
    return build;
  }).concat(found.filter((f) => f.composeBuild !== undefined).map((f) => ({ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: composeEnvWhy(f.subject) })));
}

