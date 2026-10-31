// The compose file for the services' dependencies and the runtime env that goes with it (v0.2 Plan D, D4; preflight B6, S3, S4, S7).
// When a service needs a database or a broker, pipegen writes `docker-compose.pipegen.yml`: one container per dependency kind (shared) and an
// app container per runnable npm service, built from the service's own Dockerfile. The file is FULLY COMPUTED: composeText has no AI input, and
// the referee recomputes it from the draft and requires byte equality. So every character comes from one of:
//   - a fixed table (compose-tables.ts: keys, images ids, ports, healthchecks, the `pipegen` literals, the ${NAME} references);
//   - a validated repo value: `slug(service name)` for the key, the plain service folder for `build.context`, a port integer 1..65535, and env var
//     names that pass NAME_RE, are not dangerous and are in the ENV_TABLE.
// The YAML is written by hand in a fixed key order with double-quoted strings (no YAML library stringify), so the text is byte-stable.
//
// Not proven (no file, a note): an unknown dependency kind, no runnable service, two services whose keys collide or that want one port, a dependency
// whose version is another MAJOR than the list's (never a silent downgrade or upgrade), a missing image id, or an unowned docker-compose.pipegen.yml.
// A service that does not qualify (not npm, no port, a path that is not plain, no Dockerfile) is left out with a note; the others are still written.
//
// Version rule (the list has one image per kind): the repo's version, when a reader found one, is compared with the list id's release series.
// Same series (postgres 17.x, redis 7.x, mongo 8.0.x): silent. Same major, other series (mongo 8.3, mysql 8.0): the file is written and the note says
// "pipegen uses <id>; your repo asks for <v>". Another major (postgres 16, redis 6, mongo 7): no file, the same note plus the reason. In CI the
// containers are throw-away and keep no data, so a series difference within a major can only change behaviour, which the note tells.
import { ArtifactNameError, slug } from '../engine/artifact-names.js';
import { type BaseImage, BaseImageError, baseImageRef } from '../engine/base-images.js';
import { createdPathProblem, isDangerousName } from '../engine/job-rules.js';
import { isRunnable } from '../engine/needs.js';
import { NAME_RE } from '../read/manifest.js';
import { SERVICE_NAME_RE } from '../read/project.js';
import type { CreatedFile, Dependency, RepoProfile, RuntimeEnv, Service } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { DB_PASSWORD_BYTES, DB_PASSWORD_NAME, DEP_KEYS, DEP_TABLE, ENV_TABLE, isDepKey, VALUE_TABLE, type DepKey, type VarKind } from './compose-tables.js';

export { DEP_TABLE, ENV_TABLE, VALUE_TABLE };
export const COMPOSE_PATH = 'docker-compose.pipegen.yml';

const VERSION_RE = /^\d{1,4}(?:\.\d{1,4}){0,2}$/;
const MAX_NOTE = 200;
const show = (s: unknown): string => `"${safeText(String(s), 80)}"`;

// ---------- validated repo values ----------

const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
const validPort = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= 65535;
/** A service folder a created file may sit in: a plain path (CF-1) without a hidden or node_modules segment. '' is the repo root. */
const plainFolder = (dir: string): boolean => createdPathProblem(dir === '' ? 'Dockerfile' : `${dir}/Dockerfile`) === null && !dir.split('/').some((s) => s.startsWith('.') || s === 'node_modules');

// ---------- the environment: which names pipegen fills ----------

/** A name pipegen may write into a step or a compose file at all (before the table): NAME_RE, nothing dangerous, no GITHUB_*, not the reserved password. */
const nameProblem = (name: unknown): string | null => {
  if (typeof name !== 'string' || !NAME_RE.test(name)) return 'is not a plain environment variable name';
  if (name.startsWith('GITHUB_')) return 'starts with GITHUB_, which pipegen never sets';
  if (name === DB_PASSWORD_NAME) return 'is pipegen\'s own database password variable, which is set only by its own step';
  if (isDangerousName(name)) return 'changes how code runs on the runner, which pipegen never sets';
  return null;
};

interface EnvPlan { vars: RuntimeEnv['vars']; notes: string[] }

/** The services whose dependencies the runtime env covers: the ones that run. */
const covered = (p: RepoProfile): Service[] => (Array.isArray(p?.services) ? p.services.filter((s) => s !== null && typeof s === 'object' && Array.isArray(s.dependsOn) && isRunnable(s)) : []);
const depsOf = (s: Service): (Dependency & { kind: DepKey })[] => s.dependsOn.filter((d): d is Dependency & { kind: DepKey } => d !== null && typeof d === 'object' && isDepKey(d.kind));

function planEnv(p: RepoProfile): EnvPlan {
  const notes: string[] = [];
  const claims = new Map<string, Map<DepKey, VarKind>>();
  const seenNote = new Set<string>();
  const note = (m: string): void => { if (!seenNote.has(m)) { seenNote.add(m); notes.push(m); } };
  for (const s of covered(p)) {
    for (const d of depsOf(s)) {
      for (const name of Array.isArray(d.envVars) ? d.envVars : []) {
        const bad = nameProblem(name);
        if (bad !== null) { note(`The variable ${show(name)} of the ${d.kind} dependency ${bad}, so pipegen does not fill it.`); continue; }
        const kind = Object.hasOwn(ENV_TABLE[d.kind], name) ? ENV_TABLE[d.kind][name] : undefined;
        if (kind === undefined || VALUE_TABLE[d.kind][kind] === undefined) {
          note(`The variable ${show(name)} belongs to the ${d.kind} dependency, but pipegen does not know what it holds, so it fills nothing for it and does not ask for it; set it yourself if the test run needs it.`);
          continue;
        }
        const by = claims.get(name) ?? new Map<DepKey, VarKind>();
        by.set(d.kind, kind);
        claims.set(name, by);
      }
    }
  }
  const vars: RuntimeEnv['vars'] = [];
  for (const name of [...claims.keys()].sort()) {
    const by = claims.get(name) as Map<DepKey, VarKind>;
    if (by.size > 1) { note(`The variable ${show(name)} is listed by more than one dependency (${[...by.keys()].join(', ')}), so pipegen can not tell which one it points at and fills nothing for it.`); continue; }
    const [dep, kind] = [...by.entries()][0] as [DepKey, VarKind];
    vars.push({ name, kind, dep });
  }
  return { vars, notes };
}

/** Whether the profile has a running service with a database or broker dependency pipegen starts (so the runtime-env and compose-up steps can be expected). */
export function needsCompose(p: RepoProfile): boolean { return covered(p).some((s) => depsOf(s).length > 0); }

/** The runtime env of a run that starts the compose file (B6): the generated password and the variables pipegen fills. Structured data, never shell text. */
export function runtimeEnv(p: RepoProfile): RuntimeEnv {
  return { password: { name: DB_PASSWORD_NAME, bytes: DB_PASSWORD_BYTES }, vars: planEnv(p).vars };
}
/** The notes that go with runtimeEnv: names of a covered dependency that pipegen does not fill (never guessed, never asked). */
export function runtimeEnvNotes(p: RepoProfile): string[] { return planEnv(p).notes; }

// ---------- versions ----------

/** The note for one dependency's version, and whether it rules the file out (another major). */
function versionCheck(kind: DepKey, version: unknown): { note?: string; fatal?: true } {
  const spec = DEP_TABLE[kind];
  if (version === undefined) return { note: `No ${kind} version was found in your repo, so the test run starts ${spec.id}.` };
  if (typeof version !== 'string' || !VERSION_RE.test(version)) return { note: `The ${kind} version in your repo is not a plain version number, so the test run starts ${spec.id}.` };
  const want = version.split('.').map(Number);
  const have = spec.series.split('.').map(Number);
  if (want.slice(0, have.length).every((x, i) => x === have[i])) return {};   // inside the series: 17.2 for 17, 7.2.4 for 7, and a short 8 for 8.4
  if (want[0] === have[0]) return { note: `pipegen uses ${spec.id}; your repo asks for ${version}. The test run uses the version pipegen has reviewed.` };
  return { note: `pipegen uses ${spec.id}; your repo asks for ${version}. A different major version can not be proven with it (data and behaviour differ, and pipegen never downgrades or upgrades silently), so pipegen writes no compose file.`, fatal: true };
}

// ---------- the plan ----------

interface App { key: string; context: string; port: number; deps: DepKey[]; env: string[] }
export interface ComposePlan { text: string | null; notes: string[] }

/** Whether `<dir>/Dockerfile` exists (the reader found it) or is created in this draft. Only that exact file name is the one `dockerfile: Dockerfile` builds. */
function hasDockerfile(s: Service, dir: string, created: ReadonlySet<string>): boolean {
  const path = dir === '' ? 'Dockerfile' : `${dir}/Dockerfile`;
  return s.dockerfile === path || created.has(path);
}

/**
 * The compose text for a profile, or null with the reasons. `createdDockerfiles` are the service Dockerfile paths (`api/Dockerfile`) pipegen creates in the
 * same draft; the creator and the referee's judge pass the same list, so they compute the same text.
 */
export function planCompose(p: RepoProfile, baseImages: readonly BaseImage[], createdDockerfiles: readonly string[] = []): ComposePlan {
  const notes: string[] = [];
  const note = (m: string): void => { const t = safeText(m, MAX_NOTE * 2); if (!notes.includes(t)) notes.push(t); };
  const services = Array.isArray(p?.services) ? p.services.filter((s) => s !== null && typeof s === 'object') : [];
  const created = new Set(createdDockerfiles);

  // an unknown dependency kind: pipegen can not tell what the service needs
  for (const s of services) {
    for (const d of Array.isArray(s.dependsOn) ? s.dependsOn : []) {
      if (d === null || typeof d !== 'object' || (d.kind !== 'external' && !isDepKey(d.kind))) {
        note(`The service ${show(s.name)} has a dependency of a kind pipegen does not know (${show((d as { kind?: unknown } | null)?.kind)}), so it can not prove a compose file for it.`);
        return { text: null, notes };
      }
    }
  }

  const apps: App[] = [];
  const env = runtimeEnv(p);
  for (const s of services) {
    const deps = [...new Set(depsOf(s).map((d) => d.kind))];
    if (deps.length === 0) continue;   // nothing to containerise for this service
    const who = show(s.name);
    if (!isRunnable(s)) { note(`The service ${who} does not run as a server, so it gets no container.`); continue; }
    if (s.language !== 'node' || s.packageManager !== 'npm') { note(`The service ${who} is not an npm project, and pipegen starts npm services only in this version, so it gets no container.`); continue; }
    if (typeof s.name !== 'string' || !SERVICE_NAME_RE.test(s.name)) { note(`The service name ${who} is not a plain name, so pipegen can not name a container for it.`); continue; }
    let key: string;
    try { key = `app-${slug(s.name)}`; } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; note(`The service name ${who} has no letters or digits, so pipegen can not name a container for it.`); continue; }
    const dir = typeof s.path === 'string' ? rootPrefix(s.path) : null;
    if (dir === null || !plainFolder(dir)) { note(`The folder ${show(s.path)} of the service ${who} is not a plain folder path, so pipegen does not build it in a container.`); continue; }
    if (!validPort(s.port)) { note(`The service ${who} has no usable port (an integer from 1 to 65535), so pipegen can not publish it.`); continue; }
    if (!hasDockerfile(s, dir, created)) { note(`The service ${who} has no Dockerfile at ${dir === '' ? '' : `${dir}/`}Dockerfile (existing or created now), so it gets no container.`); continue; }
    const names = new Set<string>();
    for (const d of depsOf(s)) for (const n of Array.isArray(d.envVars) ? d.envVars : []) if (env.vars.some((v) => v.name === n && v.dep === d.kind)) names.add(n);
    apps.push({ key, context: dir === '' ? '.' : dir, port: s.port, deps, env: [...names].sort() });
  }
  if (apps.length === 0) {
    if (services.some((s) => depsOf(s).length > 0)) note('No service with a database or broker dependency can run in a container here, so pipegen writes no compose file.');
    return { text: null, notes };
  }

  // collisions: two services that give one key, or want one port, could not both be started
  const keys = new Map<string, number>();
  const ports = new Map<number, number>();
  for (const a of apps) { keys.set(a.key, (keys.get(a.key) ?? 0) + 1); ports.set(a.port, (ports.get(a.port) ?? 0) + 1); }
  for (const [k, n] of keys) if (n > 1) note(`${n} services give the same container key ${k} (their names collide once cleaned), so pipegen writes no compose file.`);
  for (const [port, n] of ports) if (n > 1) note(`${n} services use port ${port}, and they could not all be published on it, so pipegen writes no compose file.`);
  if ([...keys.values(), ...ports.values()].some((n) => n > 1)) return { text: null, notes };

  // which dependency kinds, and their versions
  const kinds = DEP_KEYS.filter((k) => apps.some((a) => a.deps.includes(k)));
  let fatal = false;
  for (const k of kinds) {
    const versions = new Set<unknown>();
    for (const s of covered(p)) for (const d of depsOf(s)) if (d.kind === k && apps.some((a) => a.key === `app-${safeSlug(s.name)}`)) versions.add(d.version);
    for (const v of versions.size === 0 ? [undefined] : versions) {
      const r = versionCheck(k, v);
      if (r.note !== undefined) note(r.note);
      if (r.fatal) fatal = true;
    }
  }
  if (fatal) return { text: null, notes };

  // the images, from the list
  const refs = new Map<DepKey, string>();
  try { for (const k of kinds) refs.set(k, baseImageRef(DEP_TABLE[k].id, baseImages)); } catch (e) {
    if (!(e instanceof BaseImageError)) throw e;
    note(`pipegen's base-image list has no image for ${e.message}, so it writes no compose file.`);
    return { text: null, notes };
  }

  apps.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { text: emit(kinds, refs, apps), notes };
}

const safeSlug = (name: string): string | null => { try { return slug(name); } catch { return null; } };

/** The compose text for a profile, or null when pipegen proves nothing (see planCompose for the reasons). */
export function composeText(p: RepoProfile, baseImages: readonly BaseImage[], createdDockerfiles: readonly string[] = []): string | null {
  return planCompose(p, baseImages, createdDockerfiles).text;
}

// ---------- the text ----------

/** A YAML double-quoted string. Every value passed here is printable ASCII (a table row or a validated value), so JSON's escapes are YAML's. */
function q(s: string): string {
  if (!/^[\x20-\x7e]*$/.test(s)) throw new Error('compose: a value is not printable ASCII');
  return JSON.stringify(s);
}

function emit(kinds: readonly DepKey[], refs: ReadonlyMap<DepKey, string>, apps: readonly App[]): string {
  const out: string[] = ['services:'];
  for (const k of kinds) {
    const spec = DEP_TABLE[k];
    const h = spec.healthcheck;
    out.push(`  ${k}:`, `    image: ${q(refs.get(k) as string)}`);
    if (spec.env.length > 0) { out.push('    environment:'); for (const [n, v] of spec.env) out.push(`      ${n}: ${q(v)}`); }
    out.push('    ports:', `      - ${q(`127.0.0.1:${spec.port}:${spec.port}`)}`);
    out.push('    healthcheck:', `      test: [${h.test.map(q).join(', ')}]`, `      interval: ${q(h.interval)}`, `      timeout: ${q(h.timeout)}`, `      retries: ${h.retries}`);
    if (h.start_period !== undefined) out.push(`      start_period: ${q(h.start_period)}`);
  }
  for (const a of apps) {
    out.push(`  ${a.key}:`, '    build:', `      context: ${q(a.context)}`, '      dockerfile: "Dockerfile"');
    if (a.env.length > 0) { out.push('    environment:'); for (const n of a.env) out.push(`      ${n}: ${q('${' + n + '}')}`); }
    out.push('    ports:', `      - ${q(`127.0.0.1:${a.port}:${a.port}`)}`, '    depends_on:');
    for (const k of DEP_KEYS) if (a.deps.includes(k)) out.push(`      ${k}:`, '        condition: service_healthy');
  }
  return `${out.join('\n')}\n`;
}

// ---------- the creator ----------

export interface ComposeCtx {
  /** The repo's file list (the reader's `fileSet`): without it a file is never proven absent and nothing is created. */
  repoPaths?: ReadonlySet<string> | readonly string[];
  baseImages: readonly BaseImage[];
  /** Service Dockerfile paths pipegen creates in the same draft (D3), so their services count. */
  createdDockerfiles?: readonly string[];
  /** The install record says pipegen wrote the existing docker-compose.pipegen.yml (a re-run may rewrite it, S3). */
  ownsCompose?: boolean;
}

/** Creates docker-compose.pipegen.yml, or says why not. See the file header. */
export function createCompose(p: RepoProfile, ctx: ComposeCtx): { file: CreatedFile | null; notes: string[] } {
  if (ctx === undefined || ctx === null || ctx.repoPaths === undefined) return { file: null, notes: ['pipegen could not list the repository files, so it can not tell whether docker-compose.pipegen.yml already exists and creates no compose file.'] };
  const exists = [...ctx.repoPaths].some((x) => typeof x === 'string' && x.toLowerCase() === COMPOSE_PATH);
  if (exists && ctx.ownsCompose !== true) return { file: null, notes: [`${COMPOSE_PATH} already exists and pipegen did not write it, so pipegen leaves it alone and writes no compose file.`] };
  const plan = planCompose(p, ctx.baseImages, ctx.createdDockerfiles ?? []);
  if (plan.text === null) return { file: null, notes: plan.notes };
  return {
    file: { path: COMPOSE_PATH, content: plan.text, part: 'compose', repo: 'app', reason: 'Starts the databases and brokers your services need, and your services built from their Dockerfiles, for the test run in CI.' },
    notes: plan.notes,
  };
}
