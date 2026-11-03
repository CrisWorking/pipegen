// Plan E E3 fix round 1 (review-E3 I1, ruling E3-R2): the rules every proof workflow must pass before it can enter a tree the
// proof pushes. The jobs of these workflows run in the scratch repo (or are called from it) while the user's real test keys
// are stored there, so they are checked here whoever rendered them: the harness, Plan G's assemble (proofAppFiles), this
// project's central files (pushProofSetup), and, narrower, the compat copies.
//
// kind 'proof' (harness, assembled app workflows) and 'central' (this project's files pushed to pipelines):
// - every job with steps starts with the reviewed egress step: the bullfrog pin, its fixed inputs exactly, `allowed-domains`
//   only hosts of the reviewed egress sets, `allowed-ips` only the Docker range, nothing else (spike S8: nothing before it is
//   limited, and enable-sudo false is what keeps a later step from undoing it);
// - no job-level `container:` (the steps would run where the egress step can't hold); a job service is an image pinned by
//   digest, with no `options` or `volumes` (it starts at job setup, before the egress step, so only a reviewed image may);
// - a job that calls a reusable workflow calls a local one (checked as a file of its own) or `<owner>/pipelines/...@<sha>`
//   (checked in the central draft);
// - every step `uses` is pinned: `<path>@<40-hex sha>`, `docker://…@sha256:<digest>`, or a local `./` action;
// - no step restores or saves a cache: no actions/cache, no `cache*` input other than an explicit off, and setup-node with
//   `package-manager-cache: "false"` (E3-R2: a compat job can write the pull request's cache scope; a key-holding job must
//   never read it).
// kind 'proof' and 'compat': no trigger a person, a schedule or another event can start (FORBIDDEN_PROOF_TRIGGERS).
// kind 'central' keeps E2-R3's own trigger allowlist (checkCentralTriggers: workflow_call, workflow_dispatch, schedule; none
// of them fires on a proof/<runId> branch push, and pipegen never calls the dispatch endpoint).
// kind 'compat' (ruling E3-R2): no egress step (S17) and the user's own tag-pinned actions may stay, because a compat job
// holds no secret, has a contents: read token and its own VM; actions/cache stays refused there too.
import type { ReviewedTool } from '../types.js';
import { EGRESS_DOMAIN_SETS } from '../engine/egress.js';
import { loadReviewed } from '../engine/reviewed.js';
import { isObj, parseYaml, type Obj } from '../engine/yaml-parse.js';
import { safeText } from '../util/safe-text.js';
import { ProofStopError } from './target.js';

export type ProofWorkflowKind = 'proof' | 'compat' | 'central';
/** Triggers no proof workflow (app side) may have: each starts a run without a push or pull request of the proof. */
export const FORBIDDEN_PROOF_TRIGGERS: readonly string[] = Object.freeze(['workflow_dispatch', 'schedule', 'workflow_run', 'repository_dispatch', 'issue_comment', 'pull_request_target']);

const PINNED_USES_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/;
const DOCKER_USES_RE = /^docker:\/\/[a-z0-9][a-z0-9._/:-]{0,200}@sha256:[0-9a-f]{64}$/;
const LOCAL_ACTION_RE = /^\.\/\.github\/actions\/[A-Za-z0-9._/-]{1,200}$/;
const LOCAL_CALL_RE = /^\.\/\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml$/;
const CENTRAL_CALL_RE = /^[A-Za-z0-9-]{1,39}\/pipelines\/\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml@[0-9a-f]{40}$/;
const IMAGE_DIGEST_RE = /@sha256:[0-9a-f]{64}$/;
const DOCKER_RANGE = '172.16.0.0/12';
const CACHE_KEY_RE = /(?:^|[-_])cache(?:$|[-_])/i;
/** The cache inputs a key-holding step may carry, each only at its "off" value. */
const CACHE_OFF: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'no-cache': ['true'], 'cache-binary': ['false'], 'package-manager-cache': ['false'], cache: ['', 'false'],
});

const isWorkflowFile = (p: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(p);
const usesPath = (u: string): string => (u.includes('@') ? u.slice(0, u.lastIndexOf('@')) : u).toLowerCase();

function triggersOf(on: unknown): string[] {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.filter((t): t is string => typeof t === 'string');
  return isObj(on) ? Object.keys(on) : [];
}

function egressProblem(step: unknown, bullfrog: ReviewedTool): string | null {
  if (!isObj(step) || step.uses !== bullfrog.step.action?.uses) return 'its first step is not the reviewed egress step';
  const w = step.with;
  if (!isObj(w)) return 'the egress step has no inputs';
  const fixed = bullfrog.fixedInputs.with ?? {};
  for (const [k, v] of Object.entries(fixed)) if (w[k] !== v) return `the egress step's ${k} is not ${v}`;
  for (const k of Object.keys(w)) if (!Object.hasOwn(fixed, k) && k !== 'allowed-domains' && k !== 'allowed-ips') return `the egress step has the input ${safeText(k, 40)}`;
  if (typeof w['allowed-domains'] !== 'string') return 'the egress step has no allowed-domains list';
  const known = new Set(Object.values(EGRESS_DOMAIN_SETS).flat());
  for (const h of w['allowed-domains'].split('\n')) if (!known.has(h)) return `the egress step allows ${safeText(h, 80)}, which is in no reviewed egress set`;
  if ('allowed-ips' in w && w['allowed-ips'] !== DOCKER_RANGE) return `the egress step's allowed-ips is not ${DOCKER_RANGE}`;
  return null;
}

function cacheProblem(step: Obj, kind: ProofWorkflowKind): string | null {
  const uses = typeof step.uses === 'string' ? usesPath(step.uses) : '';
  if (uses === 'actions/cache' || uses.startsWith('actions/cache/')) return `it uses ${safeText(uses, 60)} (no proof job restores or saves a cache)`;
  if (kind === 'compat') return null;
  const w = isObj(step.with) ? step.with : {};
  for (const [k, v] of Object.entries(w)) {
    if (!CACHE_KEY_RE.test(k)) continue;
    const off = CACHE_OFF[k];
    if (off === undefined || typeof v !== 'string' || !off.includes(v)) return `a step sets the cache input ${safeText(k, 40)} (a job that may hold keys never uses a cache)`;
  }
  if (uses === 'actions/setup-node' && w['package-manager-cache'] !== 'false') return 'setup-node runs without package-manager-cache: "false" (it would restore a cache)';
  return null;
}

function jobProblems(id: string, job: unknown, kind: ProofWorkflowKind, bullfrog: ReviewedTool): string[] {
  const at = (m: string) => `job ${safeText(id, 60)}: ${m}`;
  if (!isObj(job)) return [at('it is not a map of keys')];
  const out: string[] = [];
  if (typeof job.uses === 'string' || 'uses' in job) {
    if (kind === 'compat') return [];
    const u = job.uses;
    if (typeof u !== 'string' || !(LOCAL_CALL_RE.test(u) || CENTRAL_CALL_RE.test(u))) out.push(at('it calls a reusable workflow that is neither a local proof file nor the central draft at a commit sha'));
    return out;
  }
  if (!Array.isArray(job.steps) || job.steps.length === 0) return [at('it has no steps')];
  if (kind !== 'compat') {
    const e = egressProblem(job.steps[0], bullfrog);
    if (e !== null) out.push(at(`${e} (the egress step must be the first step of every job)`));
    if ('container' in job) out.push(at('it runs in a job container, where the egress step does not hold'));
    if ('services' in job) {
      if (!isObj(job.services)) out.push(at('its services are not a map'));
      else for (const [n, svc] of Object.entries(job.services)) {
        if (!isObj(svc) || typeof svc.image !== 'string' || !IMAGE_DIGEST_RE.test(svc.image)) out.push(at(`the service ${safeText(n, 40)} is not an image pinned by digest`));
        else if ('options' in svc || 'volumes' in svc) out.push(at(`the services entry ${safeText(n, 40)} sets options or volumes`));
      }
    }
  }
  for (const s of job.steps) {
    if (!isObj(s)) { out.push(at('a step is not a map of keys')); continue; }
    if (kind !== 'compat' && 'uses' in s) {
      const u = s.uses;
      if (typeof u !== 'string' || !(PINNED_USES_RE.test(u) || DOCKER_USES_RE.test(u) || LOCAL_ACTION_RE.test(u))) out.push(at(`the action ${safeText(String(u), 120)} is not pinned by a commit sha or digest`));
    }
    const c = cacheProblem(s, kind);
    if (c !== null) out.push(at(c));
  }
  return out;
}

/** The problems of one proof workflow (empty = it may be pushed). A file outside .github/workflows/ has none. */
export function proofWorkflowProblems(file: { path: string; content: string }, kind: ProofWorkflowKind, reviewed: readonly ReviewedTool[] = loadReviewed()): string[] {
  if (!isWorkflowFile(file.path)) return [];
  const r = parseYaml(file.content, 'strict');
  if ('problems' in r) return [`pipegen can't read it strictly (${r.problems[0] ?? 'not YAML'})`];
  const wf = r.parsed.js;
  const out: string[] = [];
  if (kind !== 'central') for (const t of triggersOf(wf.on)) if (FORBIDDEN_PROOF_TRIGGERS.includes(t)) out.push(`it has the trigger ${t}, which no proof workflow may have`);
  const bullfrog = reviewed.find((t) => t.id === 'bullfrog');
  if (bullfrog === undefined) throw new ProofStopError('The reviewed list has no bullfrog entry.');
  if (!isObj(wf.jobs) || Object.keys(wf.jobs).length === 0) out.push('it has no jobs');
  else for (const [id, job] of Object.entries(wf.jobs)) out.push(...jobProblems(id, job, kind, bullfrog));
  return out;
}

/** Every proof workflow of `files` passes, or a ProofStopError naming each file and its first problems. */
export function checkProofWorkflows(files: readonly { path: string; content: string; kind: ProofWorkflowKind }[], reviewed: readonly ReviewedTool[] = loadReviewed()): void {
  const bad: string[] = [];
  for (const f of files) {
    const p = proofWorkflowProblems(f, f.kind, reviewed);
    if (p.length > 0) bad.push(`${safeText(f.path, 120)}: ${p.slice(0, 3).join('; ')}`);
  }
  if (bad.length > 0) throw new ProofStopError(`pipegen won't push a proof workflow that breaks a proof rule: ${bad.join(' | ')}`);
}
