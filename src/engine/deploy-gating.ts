// v0.2 Plan G G7 (rulings S15, G7-R1 sec I2, G7-R2 item 2, G7-R3): why a job of a user's deploy workflow waits for pipegen-verify. One
// source for the deploy layer (src/layers/deploy.ts, which gates) and the referee (which refuses a needs-only mark on a job it must not be).
// - STRONG: the job deploys, or may deploy with power of its own: the deploy detector, an environment, a secret other than the workflow
//   token, a write or OIDC permission, permissions left unset (the repository default may be write), or a call of another workflow. A STRONG
//   job is gated with the head check, and the workflow-level gap rules (job if, step if, contents) apply to it.
// - WEAK: only the runner (not one of GitHub's own image labels) or a configuration variable (`vars`, any spelling) makes it a possible
//   deploy. A WEAK job never turns the workflow into a gap: it is gated with needs (and the head check when it can take it), or left out with
//   a note when its own `if:` would defeat needs.
import { jobDeploys } from '../read/workflows.js';
import type { ExistingWorkflow } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { isDangerousName } from './job-rules.js';
import { gatedIfAllowed, triggersOf } from './referee-shared.js';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * GitHub's own runner image labels, a closed list of exact names (G7-R3 3, G7-R3b M4), from GitHub's docs page "GitHub-hosted runners
 * reference" (docs.github.com/en/actions/reference/runners/github-hosted-runners), with the retired windows-2019 and macos-13 images left out.
 * Any other label (`ubuntu-latest-arm`, `ubuntu-prod-vpc`, a larger runner's name the organization chose, `self-hosted`, a list, a map, an
 * expression, a label GitHub adds later) is a runner of the user's own: that fails safe (the job waits for the check).
 */
const HOSTED_LABELS: ReadonlySet<string> = new Set([
  'ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm',
  'windows-latest', 'windows-2025', 'windows-2022', 'windows-11-arm',
  'macos-latest', 'macos-26', 'macos-15', 'macos-14',
  'macos-latest-large', 'macos-15-large', 'macos-14-large',
  'macos-latest-xlarge', 'macos-15-xlarge', 'macos-14-xlarge',
  'macos-15-intel',
]);
export const githubHosted = (runsOn: unknown): boolean => typeof runsOn === 'string' && HOSTED_LABELS.has(runsOn);
/** A job pipegen's head check is written for (G7-R2 1c): a GitHub-hosted ubuntu label and no job container (bash, curl, jq on the fixed PATH). */
export const plainUbuntu = (job: unknown): boolean => isObj(job) && job.container === undefined && githubHosted(job['runs-on']) && String(job['runs-on']).startsWith('ubuntu-');
/** A call of another workflow (job-level `uses`): no steps of its own. */
export const callsWorkflow = (job: unknown): boolean => isObj(job) && job.uses !== undefined;
/** A job's permissions: its own, else the workflow's (undefined: the repository's default, which may be write). */
export const permissionsOf = (job: unknown, top: unknown): unknown => (isObj(job) && job.permissions !== undefined ? job.permissions : top);
/** Whether the job's token can read the branch (the head check's API call): no permissions set, read-all or write-all, or contents read or write. */
export function readsContents(job: unknown, top: unknown): boolean {
  const p = permissionsOf(job, top);
  if (p === undefined || p === 'read-all' || p === 'write-all') return true;
  return isObj(p) && (p.contents === 'read' || p.contents === 'write');
}

/**
 * Every key and string of a parsed job as raw text, one per line (G7-R3b M1): the secrets and vars scans run on what the user wrote, not on
 * JSON.stringify's escapes (which turn a newline or a tab right before `secrets` into `\n` / `\t` and defeat `\b`).
 */
function rawText(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (typeof v === 'number' || typeof v === 'boolean') out.push(String(v));
  else if (Array.isArray(v)) for (const x of v) rawText(x, out);
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) { out.push(k); rawText(x, out); }
  return out;
}

/** The STRONG reason a job may deploy (see the header), or null. `top`: the workflow's own permissions. */
export function strongReason(job: unknown, top: unknown): string | null {
  if (!isObj(job)) return 'it can not be read';
  if (jobDeploys(job)) return job.environment !== undefined && job.environment !== null ? 'it has an environment' : 'it deploys';
  if (callsWorkflow(job)) return 'it calls another workflow';
  const text = rawText(job).join('\n').replace(/\bsecrets\s*\.\s*GITHUB_TOKEN\b/gi, '');
  if (/\bsecrets\b/i.test(text)) return 'it uses a secret';
  const p = permissionsOf(job, top);
  if (p === undefined) return 'it sets no permissions, so it may get a write token';
  if (p === 'read-all') return null;
  if (!isObj(p)) return 'its permissions are not read only';
  for (const [k, v] of Object.entries(p)) if (v === 'write' || (k === 'id-token' && v !== 'none')) return 'it has a write permission or an OIDC token';
  return null;
}

/** The WEAK reason (G7-R2 item 2, G7-R3): a runner of the user's own, or a configuration variable in any spelling (`vars.X`, `vars['X']`, `VARS`, `toJSON(vars)`), or null. */
export function weakReason(job: unknown): string | null {
  if (!isObj(job)) return null;
  if (!githubHosted(job['runs-on'])) return 'it runs on a runner of its own, which may hold credentials';
  if (/\bvars\b/i.test(rawText(job).join('\n'))) return 'it reads a configuration variable (vars), which may be a deploy hook';
  return null;
}

// ---------- PL-E5: deployGating, moved from src/layers/deploy.ts (it imports it back; the referee imports it from here) ----------

export const show = (s: unknown): string => JSON.stringify(safeText(String(s), 100));
/** The permissions a user's workflow may set at the top without refusing the insert (the referee's judgeUserTop: the verify job's ceiling). */
const VERIFY_CEILING: Readonly<Record<string, number>> = Object.freeze({ contents: 1, actions: 1, packages: 1, attestations: 1 });
const LEVEL: Readonly<Record<string, number>> = Object.freeze({ none: 0, read: 1, write: 2 });

/** How a deploy workflow is started: push, workflow_run, or anything else (any trigger that is not push or workflow_run makes it `other`). */
export type DeployTrigger = 'push' | 'workflow_run' | 'other';

/** 'push' when push is the only trigger, 'workflow_run' when that is the only one, else 'other' (plan Task 4). */
export function deployTriggers(wf: Pick<ExistingWorkflow, 'triggers'>): DeployTrigger {
  const t = Array.isArray(wf.triggers) ? [...new Set(wf.triggers)] : [];
  if (t.length === 1 && t[0] === 'push') return 'push';
  if (t.length === 1 && t[0] === 'workflow_run') return 'workflow_run';
  return 'other';
}

/** Why a push trigger is not "the default branch only" (a filter of exactly that branch, no tags), or null. */
export function pushBranchProblem(on: unknown, defaultBranch: string): string | null {
  const fix = `; pipegen's check passes only on the default branch, so limit its push to \`branches: [${safeText(defaultBranch, 100)}]\``;
  const push = isObj(on) ? on.push : undefined;
  if (!isObj(push)) return `its push runs on every branch and tag${fix}`;
  if (push['branches-ignore'] !== undefined || push.tags !== undefined || push['tags-ignore'] !== undefined) return `its push also runs on tags or on other branches${fix}`;
  const b = push.branches;
  const list = typeof b === 'string' ? [b] : Array.isArray(b) ? b : null;
  if (list === null || list.length === 0) return `its push runs on every branch${fix}`;
  if (!list.every((x) => x === defaultBranch)) return `its push runs on other branches too${fix}`;
  return null;
}


/**
 * Why the parts of a user's workflow that apply to pipegen's job too refuse the insert (the referee's judgeUserTop, asked first so the
 * workflow is a gap and not a refused delivery), or null.
 */
export function userTopProblem(js: Obj, opts: { permissions?: boolean } = {}): string | null {
  const env = js.env;
  if (env !== undefined && (!isObj(env) || Object.entries(env).some(([k, v]) => isDangerousName(k) || (typeof v === 'string' && v.includes('${{'))))) return 'its workflow-wide env would reach pipegen\'s job (a name that changes how tools run, or an expression)';
  const d = js.defaults;
  if (d !== undefined) {
    const run = isObj(d) ? d.run : undefined;
    const ok = isObj(d) && Object.keys(d).every((k) => k === 'run') && isObj(run) && Object.keys(run).every((k) => k === 'shell') && (run.shell === undefined || run.shell === 'bash' || run.shell === 'sh');
    if (!ok) return 'its defaults would change how pipegen\'s steps run';
  }
  const p = js.permissions;
  // G13: a called workflow gets no job of pipegen's, so its permissions are not held to pipegen's job ceiling
  if (p !== undefined && opts.permissions !== false) {
    if (!isObj(p)) return 'it sets one permission level for every job (read-all or write-all), more than pipegen\'s job may have';
    for (const [k, v] of Object.entries(p)) {
      const level = typeof v === 'string' && Object.hasOwn(LEVEL, v) ? LEVEL[v] as number : undefined;
      if (level === undefined || level > (Object.hasOwn(VERIFY_CEILING, k) ? VERIFY_CEILING[k] as number : 0)) return 'its workflow-wide permissions are more than pipegen\'s job may have';
    }
  }
  return null;
}

/** G7-R-sec1: every step's if: of a job runs only when the steps before it passed (the job-level rule, gatedIfAllowed, per step). */
export const stepsGated = (job: unknown): boolean => isObj(job) && (!Array.isArray(job.steps) || job.steps.every((st) => !isObj(st) || gatedIfAllowed(st.if)));

/** G17 row 4 (sec r3 M3): the reason of a job when the detector names no job of the workflow and the job has no STRONG reason of its own. */
export const COULD_NOT_TELL = 'pipegen could not tell which job deploys, so every job waits';

/** Which jobs of a user's push deploy workflow wait for pipegen-verify, and how (deployGating). */
export interface DeployGating {
  /** the jobs the deploy detector names (none: every job waits) */
  found: string[];
  /** why each STRONG job waits (with the head check; the workflow-level gap rules apply to it) */
  strong: Map<string, string>;
  /** why each WEAK job may deploy (its runner or vars, or COULD_NOT_TELL) */
  weak: Map<string, string>;
  /** WEAK jobs whose own if: defeats needs: left out, with a note */
  weakOut: string[];
  /** gated jobs that wait with needs only (no head check) */
  needsOnly: string[];
  /** every job that waits for pipegen-verify, in the file's order */
  deployJobs: string[];
  /** jobs that do not wait (no reason of either kind) */
  left: string[];
}

/**
 * G17 rows 2-4 (probe R9; sec r3 M2, M3): the one derivation of what pipegen's verify insert gates in a user's deploy workflow, from its
 * parsed text and the default branch. planVerifyInserts builds the insert from it and the referee (judgeEdited) re-derives it from the mark's
 * original, so a mark never decides which jobs wait, which wait without the head check, or whether the workflow is a gap.
 * - a gap: triggers other than one push (workflow_run, or anything else), a push beyond the default branch, or a top level that would reach
 *   pipegen's job; then the per-job gap rules for STRONG jobs (an if: that defeats needs, a step if: that runs after a failure, no contents read);
 * - S15 per job (src/engine/deploy-gating.ts): STRONG jobs wait with the head check; WEAK jobs wait (head check only when they can take it) or
 *   are left out when their own if: defeats needs. When the detector names no job, each job keeps its own STRONG reason, and a job without one
 *   waits as COULD_NOT_TELL: like a WEAK job (needs, and the head check when it can take it), except that its own if: defeating needs still
 *   makes the workflow a gap (every job waits, so none may run past the check).
 */
export function deployGating(js: Obj, defaultBranch: string): DeployGating | { gap: string } {
  const triggers = triggersOf(js.on);
  if (triggers === null) return { gap: 'its triggers can not be read; write `on:` as a name, a list or a map of events' };
  const kind = deployTriggers({ triggers });
  if (kind === 'workflow_run') return { gap: 'it deploys after another workflow run (workflow_run), which runs with full rights on what that run produced, so pipegen adds no check to it; to have the check, deploy from a push to the default branch' };
  if (kind === 'other') return { gap: `it is started by ${triggers.filter((t) => t !== 'push').map((t) => safeText(t, 40)).join(', ') || 'no push'}, not only by a push, so pipegen adds no check to it; to have the check, start it only on a push to the default branch` };
  const branch = pushBranchProblem(js.on, defaultBranch);
  if (branch !== null) return { gap: branch };
  const top = userTopProblem(js);
  if (top !== null) return { gap: `pipegen can not add its job: ${top}` };
  const jobs = isObj(js.jobs) ? js.jobs : {};
  const ids = Object.keys(jobs);
  const found = ids.filter((id) => jobDeploys(jobs[id]));
  const strong = new Map<string, string>();
  const weak = new Map<string, string>();
  for (const id of ids) {
    const sr = strongReason(jobs[id], js.permissions);
    if (sr !== null) { strong.set(id, sr); continue; }
    const wr = found.length === 0 ? COULD_NOT_TELL : weakReason(jobs[id]);
    if (wr !== null) weak.set(id, wr);
  }
  const why = (id: string): string => `${show(id)} (${strong.get(id) ?? weak.get(id) ?? ''})`;
  const strongIds = [...strong.keys()];
  const jobIf = (id: string): boolean => gatedIfAllowed(isObj(jobs[id]) ? (jobs[id] as Obj).if : undefined);
  // a COULD_NOT_TELL job whose own if: defeats needs makes the workflow a gap, as a STRONG one does
  const ungated = ids.filter((id) => (strong.has(id) || weak.get(id) === COULD_NOT_TELL) && !jobIf(id));
  if (ungated.length > 0) return { gap: `its job ${ungated.map(why).join(', ')} has an if: that could run it even when pipegen's check fails (always(), failure(), or a top-level ||); change it to success() && <your condition>` };
  // G7-R-sec1: a later step whose if: can run when an earlier step failed (always(), failure(), cancelled(), a top-level ||) would still
  // deploy after pipegen's head check failed, so such a job is not protected: the workflow is a gap
  const stepIfs = strongIds.filter((id) => !callsWorkflow(jobs[id]) && !stepsGated(jobs[id]));
  if (stepIfs.length > 0) return { gap: `a step of its job ${stepIfs.map(why).join(', ')} has an if: that could run it after pipegen's head check failed (always(), failure(), cancelled(), or a top-level ||); change it to success() && <your condition>` };
  const noContents = strongIds.filter((id) => !callsWorkflow(jobs[id]) && !readsContents(jobs[id], js.permissions));
  if (noContents.length > 0) return { gap: `its job ${noContents.map(why).join(', ')} sets permissions without contents: read, which pipegen's head check in that job needs to read the branch; add contents: read to that job's permissions` };
  // G7-R3 1: a WEAK job whose own if: defeats needs is left out (said so); else it waits, with the head check only when it can take it
  const weakOut = [...weak.keys()].filter((id) => !jobIf(id));
  const weakIn = [...weak.keys()].filter((id) => !weakOut.includes(id));
  const needsOnly = weakIn.filter((id) => !(plainUbuntu(jobs[id]) && stepsGated(jobs[id]) && readsContents(jobs[id], js.permissions)));
  const deployJobs = ids.filter((id) => strong.has(id) || weakIn.includes(id));
  const left = ids.filter((id) => !strong.has(id) && !weak.has(id));
  return { found, strong, weak, weakOut, needsOnly, deployJobs, left };
}
