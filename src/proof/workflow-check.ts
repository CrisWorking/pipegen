// Plan E E3 fix rounds 1-2 (review-E3 I1, review-E3-r1 I1-r1 a-d and m1-m3; rulings E3-R2, E3-R4 amended to an allowlist,
// E3-R5, E3-R6): the rules every proof workflow must pass before it enters a tree the proof pushes. These jobs run in the
// scratch repo (or are called from it) while the user's real test keys are stored there, so they are checked whoever rendered
// them: the harness, Plan G's assemble, this project's central files, and every central file a proof workflow reaches.
//
// Kinds. `proof`: a KEY-HOLDING app-side workflow (harness, assembled). `compat`: a compat copy, never key-holding; the kind
// comes only from the compat marker harness.ts sets, never from a path. `central`: a file of the pipelines tree; when a proof
// workflow reaches it through a reusable call it gets every job rule of `proof`, else only E2-R3's trigger rule.
//
// Triggers (E3-R4 amended): `proof` and `compat` only `push`, `pull_request`, and `workflow_call` for a file that is a local
// callee of this push; `central` only E2-R3's `workflow_call`, `workflow_dispatch`, `schedule` (none fires on proof/<runId>).
// Keys are compared exactly (lower case): `Push` or `Workflow_Dispatch` is a problem; the top-level key is exactly `on`.
//
// Job rules (key-holding: `proof`, and a reached `central` file):
// - a reusable call (job `uses:`) resolves to a checked file: a local `./.github/workflows/<f>` of this batch, or
//   `<owner>/pipelines/.github/workflows/<f>@<sha>` of the pushed central tree at that sha (checked too, transitively);
// - every other job: `runs-on` one of RUNNERS; first step the reviewed egress step, with only name/id/uses/with, the bullfrog
//   pin and fixed inputs exactly, reviewed hosts only, `allowed-ips` only the Docker range; exactly one bullfrog step; no job
//   `container:`; services only images pinned by digest without options or volumes;
// - every step `uses` is a reviewed action at its reviewed pin, a reviewed image as `docker://…@digest`, or a local action
//   pipegen renders in this push (`./.github/actions/<x>` with its action.yml in the batch);
// - no `env` (workflow, job or step) sets a name in RUNTIME_ENV_NAMES (any case); BASH_ENV and ENV may only be emptied, which
//   is the renderer's own guard (render-step bashStep, render-cli runStep), never given a value;
// - `defaults.run.shell` (workflow or job) is bash or sh;
// - permissions: the job's own, or else an explicit workflow-level map of read/none only; never write-all; id-token only in
//   a job that runs the reviewed attest action;
// - no cache (E3-R2, clarified E3-R5: "no proof job restores a cache" means key-holding jobs): no actions/cache, no `cache*`
//   input but its off value, setup-node with package-manager-cache "false"; and, as a lint backstop only (a script can
//   always be written another way), no run script with a `type=gha` cache or `gh cache`.
// - E9 (ruling E3-R7): no run script bind-mounts a host path into a container (bindMountProblem; also a lint backstop);
// - E9 (carry E4-R4 R5): no string of the workflow names `vars` other than vars.PIPEGEN_BLOCK_FROM (varsProblem; whole strings).
// Compat (E3-R2): no egress step (S17) and the user's own tag-pinned actions may stay (no secret, a contents: read token, its
// own VM); `actions/cache` is still refused. A compat job may keep a setup cache: no key-holding job reads any cache.
import type { ReviewedTool } from '../types.js';
import { EGRESS_DOMAIN_SETS } from '../engine/egress.js';
import { loadReviewed } from '../engine/reviewed.js';
import { allowedDomainsProblem } from '../engine/tool-flags.js';
import { isObj, parseYaml, type Obj } from '../engine/yaml-parse.js';
import { safeText } from '../util/safe-text.js';
import { ProofStopError } from './target.js';

export type ProofWorkflowKind = 'proof' | 'compat' | 'central';
export interface ProofCheckFile { path: string; content: string; kind: ProofWorkflowKind }
export interface ProofCheckOptions {
  reviewed?: readonly ReviewedTool[];
  /**
   * The central tree this proof pushes: its commit and every workflow file in it, to resolve and check central callees.
   * 'later': a central call is checked for its shape only (proofAppFiles; pushProofSetup checks again with the tree).
   * Absent: a central call can't be resolved, so it is a problem.
   */
  central?: { sha: string; workflows: readonly { path: string; content: string }[] } | 'later';
}

/** Triggers an app-side proof workflow may have (E3-R4 amended); workflow_call only for a local callee of this push. */
export const PROOF_TRIGGERS: readonly string[] = Object.freeze(['push', 'pull_request']);
/** E2-R3's central allowlist (snapshot.ts CENTRAL_TRIGGERS): central files hold no keys and none of these fires on proof/<runId>. */
export const CENTRAL_TRIGGERS: readonly string[] = Object.freeze(['workflow_call', 'workflow_dispatch', 'schedule']);
/** The runner labels pipegen renders (referee.ts HOSTED_RUNNERS). */
export const RUNNERS: readonly string[] = Object.freeze(['ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm']);
/** Env names that change what a runtime, the shell, git or the network does (E3-R6), refused in key-holding jobs in any case. */
export const RUNTIME_ENV_NAMES: readonly string[] = Object.freeze([
  'NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'BASH_ENV', 'ENV', 'PYTHONSTARTUP', 'PYTHONPATH', 'PERL5OPT', 'RUBYOPT',
  'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'GIT_SSH_COMMAND', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY',
]);
/** The two the renderer itself EMPTIES on every run step (no ambient startup file): only the empty value is allowed. */
const EMPTY_OK: ReadonlySet<string> = new Set(['BASH_ENV', 'ENV']);

const LOCAL_CALL_RE = /^\.\/(\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml)$/;
const CENTRAL_CALL_RE = /^([A-Za-z0-9-]{1,39})\/pipelines\/(\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml)@([0-9a-f]{40})$/;
const LOCAL_ACTION_RE = /^\.\/(\.github\/actions\/[A-Za-z0-9._-]{1,100})$/;
const IMAGE_DIGEST_RE = /@sha256:[0-9a-f]{64}$/;
const DOCKER_RANGE = '172.16.0.0/12';
const CACHE_KEY_RE = /(?:^|[-_])cache(?:$|[-_])/i;
/** The cache inputs a key-holding step may carry, each only at its "off" value. */
const CACHE_OFF: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'no-cache': ['true'], 'cache-binary': ['false'], 'package-manager-cache': ['false'], cache: ['', 'false'],
});
/** Lint backstop (m1): a run script that reads or writes the Actions cache. */
const RUN_CACHE_RE = /type=gha\b|\bgh\s+cache\b|\/actions\/caches\b/i;
const EGRESS_STEP_KEYS: ReadonlySet<string> = new Set(['name', 'id', 'uses', 'with']);

// ---------- E9: bind mounts (ruling E3-R7) and vars (carry E4-R4 R5) ----------

/** The container command-line tools whose run/create can bind-mount a host path (by the base name of the word). */
const CONTAINER_CLI_RE = /^(?:.*\/)?(?:docker|podman|nerdctl)$/;
/** The `--mount` types that are not a bind mount (docker lower-cases the type value; its keys too). */
const NOT_BIND_TYPES: ReadonlySet<string> = new Set(['volume', 'tmpfs']);
/**
 * Security scan (E9): why a `--mount` value may hold a bind mount, or null. The value is read as docker's comma-separated key=value
 * list (docker lower-cases the keys), never matched as a whole: `type` must appear exactly once and be volume or tmpfs; a volume
 * option or driver (`volume-opt=o=bind,volume-opt=device=/` makes the local driver bind a host path) and any bind-* key are refused;
 * an empty field, a quote (docker's CSV reader would read quoted fields another way) or a missing value is unparseable, so refused.
 */
function mountProblem(raw: string | undefined): string | null {
  if (raw === undefined) return 'a --mount with no value';
  let v = raw;
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v.at(-1) === v[0]) v = v.slice(1, -1);
  if (v === '' || /["']/.test(v)) return 'a --mount value pipegen can not read (quotes)';
  let types = 0;
  for (const field of v.split(',')) {
    if (field === '') return 'a --mount value with an empty field';
    const eq = field.indexOf('=');
    const key = (eq < 0 ? field : field.slice(0, eq)).toLowerCase();
    if (key === 'type') {
      types++;
      if (eq < 0 || !NOT_BIND_TYPES.has(field.slice(eq + 1).toLowerCase())) return 'a --mount whose type is not volume or tmpfs';
    } else if (key === 'volume-opt' || key === 'volume-driver' || key.startsWith('bind')) return `a --mount with ${safeText(key, 30)} (a volume option or driver can bind a host path)`;
  }
  return types === 1 ? null : 'a --mount without exactly one type';
}
/**
 * E9 (ruling E3-R7): why a run script bind-mounts a host path into a container, or null. Bullfrog with sudo off refuses those at run
 * time, and pipegen's own steps copy folders in instead (render-cli.ts), so a mount means a script pipegen did not render. A lint read
 * (a script can always be written another way), strict on purpose: line continuations are joined, the script is cut into simple
 * commands at `;`, `&`, `|`, newlines, parentheses and backquotes, and after a docker/podman/nerdctl word every `-v` (alone, with its
 * value attached, or last in a short-flag group), `--volume` and `--volumes-from` counts whatever its source (a named volume too),
 * wherever it stands (also in the container's own command); a `--mount` counts unless mountProblem reads it as a plain volume or tmpfs;
 * and `volume create` with a driver or an option (`-o`, `--opt`, `-d`, `--driver`) counts (the local driver's options bind a host path).
 */
export function bindMountProblem(script: string): string | null {
  const commands = script.replace(/\\\r?\n/g, ' ').split(/\|\||&&|\$\(|[;|&()`\n]/);
  for (const c of commands) {
    const raws = c.split(/\s+/).filter((w) => w !== '');
    const words = raws.map((w) => w.replace(/["']/g, ''));
    const at = words.findIndex((w) => CONTAINER_CLI_RE.test(w));
    if (at < 0) continue;
    const volumeCreate = words.slice(at + 1).join(' ').match(/(?:^| )volume create(?: |$)/) !== null;
    for (let i = at + 1; i < words.length; i++) {
      const w = words[i] as string;
      if (/^-(?!-)[A-Za-z]*v/.test(w) || /^--(?:volume|volumes-from)(?:=|$)/.test(w)) return `a run script bind-mounts a host path into a container (${safeText(w, 40)})`;
      if (volumeCreate && /^(?:-o|--opt|-d|--driver)(?:=|$)|^-[od]./.test(w)) return `a run script creates a volume with a driver or an option (${safeText(w, 40)}), which can bind a host path`;
      if (/^--mount(?:=|$)/.test(w)) {
        const r = raws[i] as string;
        const eq = r.indexOf('=');
        const problem = mountProblem(eq >= 0 && /^["']?--mount=/.test(r) ? r.slice(eq + 1).replace(/^(["'])(.*)\1$/, '$2') : raws[i + 1]);
        if (problem !== null) return `a run script may bind-mount a host path into a container (${problem})`;
      }
    }
  }
  return null;
}

/** Every string of a parsed workflow, keys included, decoded (YAML scalars as the runner reads them). */
function stringsOf(v: unknown, out: string[]): void {
  if (typeof v === 'string') { out.push(v); return; }
  if (Array.isArray(v)) { for (const x of v) stringsOf(x, out); return; }
  if (isObj(v)) for (const [k, x] of Object.entries(v)) { out.push(k); stringsOf(x, out); }
}
/**
 * Carry E4-R4 R5: the one `vars` reference a key-holding workflow may make is `vars.PIPEGEN_BLOCK_FROM` (the gate's block-from input).
 * Organisation and repository variables are not listed or emptied by the scratch-key checks, so any other one (a name, an index, the
 * whole context in toJSON(vars), any case) could carry a value nobody checked into a job beside the keys.
 */
function varsProblem(wf: Obj): string | null {
  // Security scan (E9): the whole of every string is searched, never only between `${{` and the first `}}` (a `}}` inside a quoted
  // literal, `format('}}', vars.X)`, would end that search early). Strict on purpose: the word vars anywhere else is refused too.
  const texts: string[] = [];
  stringsOf(wf, texts);
  for (const t of texts) {
    const rest = t.replace(/\bvars\s*\.\s*PIPEGEN_BLOCK_FROM\b/gi, '');
    const m = /\bvars\b/i.exec(rest);
    if (m !== null) return `it names vars other than vars.PIPEGEN_BLOCK_FROM (${safeText(rest.slice(Math.max(0, m.index - 30), m.index + 50).trim(), 80)}); a key-holding workflow reads no other variable`;
  }
  return null;
}

const isWorkflowFile = (p: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(p);
const usesPath = (u: string): string => (u.includes('@') ? u.slice(0, u.lastIndexOf('@')) : u).toLowerCase();

// ---------- compat marker (m3) ----------

const compatCopies = new WeakSet<object>();
function deepFreeze<T>(v: T): T {
  if (typeof v === 'object' && v !== null && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const x of Object.values(v as object)) deepFreeze(x);
  }
  return v;
}
/**
 * harness.ts marks each compat copy it renders (and only there: a source scan checks it). The record is frozen, deeply
 * (fix round 4, C1): its content can't be edited in place, so any edit makes a new object, which is unmarked and checked as
 * key-holding. A write to a frozen field throws (ES modules are strict).
 */
export function markCompatCopy<T extends object>(f: T): Readonly<T> {
  deepFreeze(f);
  compatCopies.add(f);
  return f;
}

/**
 * A reference to the secrets context other than secrets.GITHUB_TOKEN, anywhere in a text (fix round 4, C1): `secrets` followed
 * by `.`, `[`, `)`, `}`, `,`, a comparison or the end of a line, in any case. A compat copy holds none (S17).
 */
export function namesSecret(text: string): boolean {
  return /\bsecrets\s*(?:[.[),}!=<>&|]|$)/im.test(text.replace(/\bsecrets\s*\.\s*github_token\b/gi, ''));
}
/** The runner labels a compat copy may run on (S17, plan Task 2): one plain GitHub-hosted label. */
export const COMPAT_RUNNER_RE = /^(?:ubuntu|windows|macos)-[a-z0-9][a-z0-9.-]{0,40}$/;
const READ_ONLY = (p: unknown): boolean => isObj(p) && Object.keys(p).length === 1 && p.contents === 'read';
/** Whether `f` is a compat copy harness.ts rendered (by identity, never by path). Anything else is checked as key-holding. */
export const isCompatCopy = (f: unknown): boolean => typeof f === 'object' && f !== null && compatCopies.has(f);

// ---------- the reviewed sources (d) ----------

interface Reviewed { bullfrog: ReviewedTool; actions: ReadonlySet<string>; images: ReadonlySet<string>; attest: ReadonlySet<string> }
function reviewedSources(list: readonly ReviewedTool[]): Reviewed {
  const bullfrog = list.find((t) => t.id === 'bullfrog');
  if (bullfrog === undefined || bullfrog.step.action === undefined) throw new ProofStopError('The reviewed list has no bullfrog entry.');
  const actions = new Set<string>();
  const images = new Set<string>();
  const attest = new Set<string>();
  for (const t of list) {
    if (t.candidate.source !== 'reviewed' || t.candidate.reviewed !== true) continue;
    const a = t.step.action?.uses;
    if (a !== undefined) {
      actions.add(a.toLowerCase());
      if (t.categories.includes('attestation')) attest.add(a.toLowerCase());
    }
    const i = t.step.cli?.install;
    const d = t.candidate.pin.digest;
    if (i !== undefined && i.method === 'docker' && d !== undefined) {
      images.add(`docker://${i.package}@${d}`.toLowerCase());
      const tagged = `${i.package}:${i.version}`;
      images.add(`docker://${tagged}@${d}`.toLowerCase());
    }
  }
  return { bullfrog, actions, images, attest };
}

// ---------- one workflow ----------

interface Parsed { path: string; kind: ProofWorkflowKind; wf: Obj | null; problems: string[]; text?: string }

function triggersOf(on: unknown): string[] | null {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.every((t) => typeof t === 'string') ? on as string[] : null;
  return isObj(on) ? Object.keys(on) : null;
}

function egressProblem(steps: readonly unknown[], r: Reviewed): string | null {
  const step = steps[0];
  const uses = r.bullfrog.step.action?.uses;
  if (!isObj(step) || step.uses !== uses) return 'its first step is not the reviewed egress step';
  for (const k of Object.keys(step)) if (!EGRESS_STEP_KEYS.has(k)) return `the egress step has the key ${safeText(k, 40)} (only name, id, uses and with: nothing may skip or change it)`;
  const w = step.with;
  if (!isObj(w)) return 'the egress step has no inputs';
  const fixed = r.bullfrog.fixedInputs.with ?? {};
  for (const [k, v] of Object.entries(fixed)) if (w[k] !== v) return `the egress step's ${k} is not ${v}`;
  for (const k of Object.keys(w)) if (!Object.hasOwn(fixed, k) && k !== 'allowed-domains' && k !== 'allowed-ips') return `the egress step has the input ${safeText(k, 40)}`;
  if (typeof w['allowed-domains'] !== 'string') return 'the egress step has no allowed-domains list';
  // E9 (ruling B5): the bundled rule, against every reviewed set (whole sets only, sorted, each host once, github-core among them)
  const domains = allowedDomainsProblem(w['allowed-domains'], Object.keys(EGRESS_DOMAIN_SETS));
  if (domains !== null) return `the egress step's ${domains}`;
  if ('allowed-ips' in w && w['allowed-ips'] !== DOCKER_RANGE) return `the egress step's allowed-ips is not ${DOCKER_RANGE}`;
  const bullfrogPath = usesPath(uses ?? '');
  if (steps.filter((s) => isObj(s) && typeof s.uses === 'string' && usesPath(s.uses) === bullfrogPath).length !== 1) return 'it has more than one bullfrog step (exactly one bullfrog step per job)';
  return null;
}

function envProblems(env: unknown, where: string): string[] {
  if (env === undefined) return [];
  if (!isObj(env)) return [`${where} env is not a map of names`];
  const out: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    const name = RUNTIME_ENV_NAMES.find((n) => n.toLowerCase() === k.toLowerCase());
    if (name === undefined) continue;
    if (EMPTY_OK.has(k) && v === '') continue;   // the renderer's own guard: emptied, exactly in upper case
    out.push(`${where} env sets ${safeText(k, 40)}, which changes how a runtime, the shell, git or the network behaves`);
  }
  return out;
}

function shellProblem(defaults: unknown, where: string): string | null {
  if (defaults === undefined) return null;
  if (!isObj(defaults)) return `${where} defaults are not a map`;
  const run = defaults.run;
  if (run === undefined) return null;
  if (!isObj(run)) return `${where} defaults.run is not a map`;
  if ('shell' in run && run.shell !== 'bash' && run.shell !== 'sh') return `${where} defaults.run.shell is ${safeText(String(run.shell), 40)} (only bash or sh)`;
  return null;
}

const minimalPermissions = (p: unknown): boolean => isObj(p) && Object.values(p).every((v) => v === 'read' || v === 'none');

function permissionProblem(job: Obj, wfPerms: unknown, r: Reviewed): string | null {
  const own = job.permissions;
  if (own === undefined) return minimalPermissions(wfPerms) ? null : 'it has no permissions of its own and the workflow\'s are not an explicit read-only map';
  if (own === 'write-all') return 'its permissions are write-all';
  if (own === 'read-all') return null;
  if (!isObj(own)) return 'its permissions are in a form pipegen does not read';
  const idt = own['id-token'];
  if (idt !== undefined && idt !== 'none') {
    const steps = Array.isArray(job.steps) ? job.steps : [];
    const attests = steps.some((s) => isObj(s) && typeof s.uses === 'string' && r.attest.has(s.uses.toLowerCase()));
    if (!attests) return 'it asks for an id-token without running the reviewed attest action';
  }
  return null;
}

/** Problems of one job, and the callee it reaches (kind of resolution and path), if it is a reusable call. */
function jobProblems(id: string, job: unknown, p: Parsed, r: Reviewed, localActions: ReadonlySet<string>): { problems: string[]; call?: { local: string } | { central: string; owner: string; sha: string } } {
  const at = (m: string) => `job ${safeText(id, 60)}: ${m}`;
  if (!isObj(job)) return { problems: [at('it is not a map of keys')] };
  const out: string[] = [];
  const keyHolding = p.kind !== 'compat';
  if (!keyHolding) {
    // fix round 4 (C1): the S17 invariants, re-asserted on the content every time
    if ('uses' in job) out.push(at('a compat job calls a reusable workflow'));
    if ('environment' in job) out.push(at('a compat job uses an environment'));
    if (!READ_ONLY(job.permissions)) out.push(at('a compat job\'s permissions are not exactly contents: read'));
    const ro = job['runs-on'];
    if (typeof ro !== 'string' || !COMPAT_RUNNER_RE.test(ro)) out.push(at('a compat job\'s runs-on is not one plain GitHub-hosted label'));
    if ('uses' in job) return { problems: out };
  }
  if ('uses' in job) {
    const perm = permissionProblem(job, p.wf?.permissions, r);
    if (perm !== null) out.push(at(perm));
    const u = job.uses;
    const local = typeof u === 'string' ? LOCAL_CALL_RE.exec(u) : null;
    const central = typeof u === 'string' ? CENTRAL_CALL_RE.exec(u) : null;
    if (local !== null) return { problems: out, call: { local: local[1] as string } };
    if (central !== null) return { problems: out, call: { central: central[2] as string, owner: central[1] as string, sha: central[3] as string } };
    out.push(at('it calls a reusable workflow that is neither a local proof file nor the central draft at a commit sha'));
    return { problems: out };
  }
  if (!Array.isArray(job.steps) || job.steps.length === 0) return { problems: [at('it has no steps')] };
  if (keyHolding) {
    const e = egressProblem(job.steps, r);
    if (e !== null) out.push(at(`${e} (the egress step must be the first step of every job)`));
    const ro = job['runs-on'];
    if (typeof ro !== 'string' || !RUNNERS.includes(ro)) out.push(at(`its runs-on is not one of the GitHub-hosted labels pipegen renders (${RUNNERS.join(', ')})`));
    if ('container' in job) out.push(at('it runs in a job container, where the egress step does not hold'));
    if ('services' in job) {
      if (!isObj(job.services)) out.push(at('its services are not a map'));
      else for (const [n, svc] of Object.entries(job.services)) {
        if (!isObj(svc) || typeof svc.image !== 'string' || !IMAGE_DIGEST_RE.test(svc.image)) out.push(at(`the service ${safeText(n, 40)} is not an image pinned by digest`));
        else if ('options' in svc || 'volumes' in svc) out.push(at(`the services entry ${safeText(n, 40)} sets options or volumes`));
      }
    }
    out.push(...envProblems(job.env, 'the job').map(at));
    const sh = shellProblem(job.defaults, 'the job');
    if (sh !== null) out.push(at(sh));
    const perm = permissionProblem(job, p.wf?.permissions, r);
    if (perm !== null) out.push(at(perm));
  }
  for (const s of job.steps) {
    if (!isObj(s)) { out.push(at('a step is not a map of keys')); continue; }
    const uses = typeof s.uses === 'string' ? s.uses : undefined;
    if (uses !== undefined && usesPath(uses).replace(/\/(restore|save)$/, '') === 'actions/cache') out.push(at(`it uses ${safeText(uses, 80)} (no proof job restores or saves a cache)`));
    if (!keyHolding) continue;
    if ('uses' in s) {
      const local = typeof s.uses === 'string' ? LOCAL_ACTION_RE.exec(s.uses) : null;
      const ok = uses !== undefined && (r.actions.has(uses.toLowerCase()) || r.images.has(uses.toLowerCase()) || (local !== null && localActions.has(local[1] as string)));
      if (!ok) out.push(at(`the action ${safeText(String(s.uses), 120)} is not a reviewed action at its reviewed pin, a reviewed image by digest, or a local action pipegen renders`));
    }
    out.push(...envProblems(s.env, 'a step').map(at));
    const w = isObj(s.with) ? s.with : {};
    for (const [k, v] of Object.entries(w)) {
      if (!CACHE_KEY_RE.test(k)) continue;
      const off = CACHE_OFF[k];
      if (off === undefined || typeof v !== 'string' || !off.includes(v)) out.push(at(`a step sets the cache input ${safeText(k, 40)} (a key-holding job never uses a cache)`));
    }
    if (uses !== undefined && usesPath(uses) === 'actions/setup-node' && w['package-manager-cache'] !== 'false') out.push(at('setup-node runs without package-manager-cache: "false" (it would restore a cache)'));
    if (typeof s.run === 'string' && RUN_CACHE_RE.test(s.run)) out.push(at('a run script uses the Actions cache (type=gha or gh cache)'));
    const bind = typeof s.run === 'string' ? bindMountProblem(s.run) : null;
    if (bind !== null) out.push(at(`${bind}; Bullfrog refuses it with sudo off, and pipegen copies folders in instead (ruling E3-R7)`));
  }
  return { problems: out };
}

function parse(path: string, content: string, kind: ProofWorkflowKind): Parsed {
  const r = parseYaml(content, 'strict');
  if ('problems' in r) return { path, kind, wf: null, problems: [`pipegen can't read it strictly (${r.problems[0] ?? 'not YAML'})`] };
  return { path, kind, wf: r.parsed.js, problems: [], text: content };
}

function triggerProblems(p: Parsed, localCallee: boolean): string[] {
  const wf = p.wf as Obj;
  const onKeys = Object.keys(wf).filter((k) => k.toLowerCase() === 'on' || k === 'true');
  if (onKeys.length !== 1 || onKeys[0] !== 'on') return ['its trigger key is not exactly `on` (one, lower case)'];
  const triggers = triggersOf(wf.on);
  if (triggers === null || triggers.length === 0) return ['its triggers are not a name, a list of names or a map'];
  const allowed = p.kind === 'central' ? CENTRAL_TRIGGERS : localCallee ? [...PROOF_TRIGGERS, 'workflow_call'] : PROOF_TRIGGERS;
  const out: string[] = [];
  for (const t of triggers) if (!allowed.includes(t)) out.push(`it has the trigger ${safeText(t, 40)}, which a ${p.kind === 'central' ? 'central' : 'proof'} workflow may not have (allowed: ${allowed.join(', ')})`);
  return out;
}

function workflowRules(p: Parsed, r: Reviewed, localActions: ReadonlySet<string>, localCallee: boolean): { problems: string[]; calls: ({ local: string } | { central: string; owner: string; sha: string })[] } {
  if (p.wf === null) return { problems: p.problems, calls: [] };
  const wf = p.wf;
  const problems = [...triggerProblems(p, localCallee)];
  if (p.kind === 'compat') {
    if (wf.on !== 'pull_request') problems.push('a compat copy\'s trigger is not exactly pull_request');
    if (!READ_ONLY(wf.permissions)) problems.push('a compat copy\'s permissions are not exactly contents: read');
    if (p.text !== undefined && namesSecret(p.text)) problems.push('a compat copy names a secret other than GITHUB_TOKEN');
  }
  if (p.kind !== 'compat') {
    const vars = varsProblem(wf);
    if (vars !== null) problems.push(vars);
    problems.push(...envProblems(wf.env, 'the workflow'));
    const sh = shellProblem(wf.defaults, 'the workflow');
    if (sh !== null) problems.push(sh);
  }
  const calls: ({ local: string } | { central: string; owner: string; sha: string })[] = [];
  if (!isObj(wf.jobs) || Object.keys(wf.jobs).length === 0) problems.push('it has no jobs');
  else for (const [id, job] of Object.entries(wf.jobs)) {
    const j = jobProblems(id, job, p, r, localActions);
    problems.push(...j.problems);
    if (j.call !== undefined) calls.push(j.call);
  }
  return { problems, calls };
}

/**
 * The problems of each workflow of a batch (empty problems = it may be pushed), with every reusable callee resolved and
 * checked transitively: a local callee must be a key-holding file of the batch; a central callee must be in
 * `opts.central` at its sha (then it is checked as a reached central file). Files outside .github/workflows/ are not judged,
 * but `.github/actions/<x>/action.y(a)ml` among them makes `./.github/actions/<x>` a local action pipegen renders.
 */
export function proofWorkflowsProblems(files: readonly ProofCheckFile[], opts: ProofCheckOptions = {}): { path: string; problems: string[] }[] {
  const r = reviewedSources(opts.reviewed ?? loadReviewed());
  const localActions = new Set(files.map((f) => /^(\.github\/actions\/[A-Za-z0-9._-]{1,100})\/action\.ya?ml$/.exec(f.path)?.[1]).filter((x): x is string => x !== undefined));
  const batch = files.filter((f) => isWorkflowFile(f.path)).map((f) => parse(f.path, f.content, f.kind));
  const byPath = new Map(batch.map((p) => [p.path, p]));
  // the local callees named by a key-holding file of the batch (workflow_call is allowed only on them)
  const localCallees = new Set<string>();
  for (const p of batch) {
    if (p.kind === 'compat' || p.wf === null || !isObj(p.wf.jobs)) continue;
    for (const job of Object.values(p.wf.jobs)) if (isObj(job) && typeof job.uses === 'string') { const m = LOCAL_CALL_RE.exec(job.uses); if (m !== null) localCallees.add(m[1] as string); }
  }
  const results = new Map<string, string[]>();
  const central = opts.central;
  const centralFiles = new Map<string, Parsed>();
  const reachedCentral: string[] = [];
  const reach = (from: Parsed, calls: ReturnType<typeof workflowRules>['calls'], add: (m: string) => void): void => {
    for (const c of calls) {
      if ('local' in c) {
        if (from.kind === 'central') {
          if (central === undefined || central === 'later') { if (central === undefined) add(`it calls ${c.local}, which pipegen can not resolve in the central tree`); continue; }
          if (!central.workflows.some((w) => w.path === c.local)) add(`it calls ${c.local}, which is not in the central tree`);
          else reachedCentral.push(c.local);
          continue;
        }
        const target = byPath.get(c.local);
        if (target === undefined) add(`it calls ${c.local}, which is not a proof file checked in this push`);
        else if (target.kind !== 'proof') add(`it calls ${c.local}, which is not a key-holding proof file pipegen rendered`);
        continue;
      }
      if (central === 'later') continue;
      if (central === undefined) { add(`it calls the central ${c.central}, which pipegen can not resolve here (no central tree)`); continue; }
      if (c.sha !== central.sha) { add(`it calls the central ${c.central} at ${c.sha}, which is not the proof's central commit`); continue; }
      if (!central.workflows.some((w) => w.path === c.central)) { add(`it calls the central ${c.central}, which is not in the central tree`); continue; }
      reachedCentral.push(c.central);
    }
  };
  for (const p of batch) {
    const out = workflowRules(p, r, localActions, localCallees.has(p.path));
    const problems = [...out.problems];
    reach(p, out.calls, (m) => problems.push(m));
    results.set(p.path, problems);
  }
  // the central files reached, transitively: every job rule of a key-holding file, with E2-R3's triggers
  if (central !== undefined && central !== 'later') {
    for (let i = 0; i < reachedCentral.length; i++) {
      const path = reachedCentral[i] as string;
      if (centralFiles.has(path)) continue;
      const w = central.workflows.find((x) => x.path === path);
      if (w === undefined) continue;
      const p = parse(path, w.content, 'central');
      centralFiles.set(path, p);
      const out = workflowRules(p, r, new Set(), false);
      const problems = [...out.problems];
      reach(p, out.calls, (m) => problems.push(m));
      results.set(`central:${path}`, problems);
    }
  }
  return [...results].map(([path, problems]) => ({ path, problems }));
}

/** The problems of one proof workflow on its own (no callee resolves outside it). A file outside .github/workflows/ has none. */
export function proofWorkflowProblems(file: { path: string; content: string }, kind: ProofWorkflowKind, reviewed: readonly ReviewedTool[] = loadReviewed()): string[] {
  return proofWorkflowsProblems([{ ...file, kind }], { reviewed }).flatMap((x) => x.problems);
}

/** Every proof workflow of `files` (and every central file they reach) passes, or a ProofStopError naming each file and its first problems. */
export function checkProofWorkflows(files: readonly ProofCheckFile[], opts: ProofCheckOptions = {}): void {
  const bad = proofWorkflowsProblems(files, opts).filter((x) => x.problems.length > 0).map((x) => `${safeText(x.path, 120)}: ${x.problems.slice(0, 3).join('; ')}`);
  if (bad.length > 0) throw new ProofStopError(`pipegen won't push a proof workflow that breaks a proof rule: ${bad.join(' | ')}`);
}
