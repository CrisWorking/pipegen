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

interface ComposeService { context: string | null; file: string | null; target: string | null; hasBuild: boolean }
export type ComposeModel = ReadonlyMap<string, ComposeService> | 'unreadable' | 'missing';
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
      for (const [name, raw] of Object.entries(asObj(doc.services)).slice(0, MAX_COMPOSE_SERVICES)) {
        const svc = asObj(raw);
        const prev = out.get(name);
        if (!('build' in svc) || svc.build === null || svc.build === undefined) {
          if (prev === undefined) out.set(name, { context: null, file: null, target: null, hasBuild: false });
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
        out.set(name, { context: folder, file, target, hasBuild: true });
      }
    }
    return out;
  })();
  ctx.composeMemo.set(key, model);
  return model;
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
  const model = await composeModel(ctx, run.files, run.cwd);
  if (model === 'missing') return null; // the runner fails: nothing runs
  const svc = model === 'unreadable' ? undefined : model.get(run.service);
  if (svc === undefined || !svc.hasBuild || svc.context === null) {
    const why = model === 'unreadable' ? "a compose file pipegen couldn't read" : svc === undefined ? `a service (${run.service}) that isn't in the compose file`
      : !svc.hasBuild ? `a service (${run.service}) that uses a ready-made image` : "a service whose build folder pipegen can't place";
    return { categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: null, reason: null, partialWhy: `${f.subject} runs in ${why}, so pipegen can't tell which service it checks.` };
  }
  const { composeRun: _placed, ...rest } = f;
  void _placed;
  return { ...rest, dir: svc.context };
}

// ---------- Dockerfiles ----------

interface Run { text: string; dir: string | null }
interface Stage { name: string | null; needs: string[]; runs: Run[] }
type Parsed = { stages: Stage[] } | { unreadable: string };

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
  if (/^\s*#\s*escape\s*=/im.test(raw.slice(0, 5).join('\n'))) return { unreadable: 'it changes the escape character' };
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
  interface State { workdir: string | null; maps: { dest: string; host: string }[] }
  const states: State[] = [];
  let cur: Stage | null = null;
  let state: State = { workdir: '/', maps: [] };
  let runs = 0;
  const refOf = (ref: string): number | null => {
    const lower = ref.toLowerCase();
    if (names.has(lower)) return names.get(lower) as number;
    return /^\d{1,2}$/.test(ref) && Number(ref) < stages.length ? Number(ref) : null;
  };
  const hostOf = (workdir: string | null): string | null => {
    if (workdir === null) return null;
    let best: { dest: string; host: string } | null = null;
    for (const m of state.maps) if ((workdir === m.dest || workdir.startsWith(`${m.dest === '/' ? '' : m.dest}/`)) && (best === null || m.dest.length >= best.dest.length)) best = m;
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
      cur = { name, needs: parent === null ? [] : [String(parent)], runs: [] };
      state = parent === null ? { workdir: '/', maps: [] } : { workdir: states[parent]!.workdir, maps: [...states[parent]!.maps] };
      if (name !== null) names.set(name.toLowerCase(), stages.length);
      stages.push(cur);
      states.push(state);
      continue;
    }
    if (cur === null) continue; // ARG before the first FROM
    if (op === 'SHELL') return { unreadable: 'it changes the shell RUN uses' };
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
      if (sources.length === 1 || destIsDir) {
        const src = sources[0] as string;
        if (sources.length === 1 && !/[*?$]|^[a-z][a-z0-9+.-]*:\/\//i.test(src) && !src.startsWith('/')) {
          const host = resolveDir(context, src.replace(/\/+$/, '') || '.');
          const kind = host === null ? null : await ctx.scriptRead.kind(host);
          if (kind === 'dir') state.maps.push({ dest, host: host as string });
          else if (kind === 'file' && destIsDir) state.maps.push({ dest, host: posix.dirname(host as string) });
        }
      }
      continue;
    }
    if (op === 'RUN') {
      if (++runs > MAX_RUNS) return { unreadable: 'it has more RUN lines than pipegen reads' };
      const { flags } = leadingFlags(rest);
      for (const f of flags) {
        const mount = /^--mount=(.*)$/i.exec(f);
        const from = mount === null ? undefined : /(?:^|,)from=([^,]+)/.exec(mount[1] as string)?.[1];
        const at = from === undefined ? null : refOf(from);
        if (at !== null && !cur.needs.includes(String(at))) cur.needs.push(String(at));
      }
      const text = runText(leadingFlags(rest).rest);
      if (text !== null) cur.runs.push({ text, dir: hostOf(state.workdir) });
    }
  }
  return { stages };
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
  const key = `docker\u0000${b.file}\u0000${b.context}\u0000${b.target ?? ''}`;
  let runs = ctx.scriptMemo.get(key);
  if (runs === undefined) {
    ctx.scriptMemo.set(key, []); // being worked out
    if (!spend(ctx)) {
      runs = unknown(`There are more files than pipegen follows, so it can't tell what the Dockerfile ${b.file} runs.`);
    } else {
      const t = await ctx.scriptRead.text(b.file);
      if ('fail' in t) {
        runs = t.fail === 'missing' ? [] : unknown(`${f.subject} builds the Dockerfile ${b.file}, which pipegen couldn't read (a symbolic link, too large or outside the repo), so it can't tell what it runs.`);
      } else {
        const parsed = await parseDockerfile(ctx, t.ok, b.context);
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
              const inner = gated(await resolve(ctx, scanned), gateOf([run.text], [], undefined, ctx.sigs.softEnv, ctx.sigs.configFiles));
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
    const model = await composeModel(ctx, f.composeBuild.files, f.composeBuild.cwd);
    if (model === 'unreadable') {
      return [{ categories: UNKNOWN_SCRIPT_CATEGORIES, by: f.by, subject: f.subject, dir: f.dir, reason: null, partialWhy: `${f.subject} uses a compose file pipegen couldn't read, so it can't tell what the Dockerfiles run.` }];
    }
    if (model !== 'missing') {
      const names = f.composeBuild.services ?? [...model.keys()];
      for (const name of names.slice(0, MAX_COMPOSE_SERVICES)) {
        const svc = model.get(name);
        if (svc === undefined || !svc.hasBuild) continue;
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
  return out;
}

