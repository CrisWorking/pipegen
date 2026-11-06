// v0.2 Plan G G7 (rulings S15, G7-R1 sec I2, G7-R2 item 2, G7-R3): why a job of a user's deploy workflow waits for pipegen-verify. One
// source for the deploy layer (src/layers/deploy.ts, which gates) and the referee (which refuses a needs-only mark on a job it must not be).
// - STRONG: the job deploys, or may deploy with power of its own: the deploy detector, an environment, a secret other than the workflow
//   token, a write or OIDC permission, permissions left unset (the repository default may be write), or a call of another workflow. A STRONG
//   job is gated with the head check, and the workflow-level gap rules (job if, step if, contents) apply to it.
// - WEAK: only the runner (not one of GitHub's own image labels) or a configuration variable (`vars`, any spelling) makes it a possible
//   deploy. A WEAK job never turns the workflow into a gap: it is gated with needs (and the head check when it can take it), or left out with
//   a note when its own `if:` would defeat needs.
import { jobDeploys } from '../read/workflows.js';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * GitHub's own runner image labels, a closed list (G7-R3 3): ubuntu latest/24.04/22.04 (and -arm), windows latest/2025/2022/2019 and 11-arm,
 * macos latest/26/15/14/13 (and the documented -large, -xlarge and -intel). A label of any other shape (`ubuntu-prod-vpc`, a larger runner's
 * name the organization chose, `self-hosted`, a list, a map, an expression) is a runner of the user's own.
 */
const HOSTED_RE = /^(?:ubuntu-(?:latest|24\.04|22\.04)(?:-arm)?|windows-(?:latest|2025|2022|2019)|windows-11-arm|macos-(?:latest|26|15|14|13)(?:-large|-xlarge|-intel)?)$/;
export const githubHosted = (runsOn: unknown): boolean => typeof runsOn === 'string' && HOSTED_RE.test(runsOn);
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

/** The STRONG reason a job may deploy (see the header), or null. `top`: the workflow's own permissions. */
export function strongReason(job: unknown, top: unknown): string | null {
  if (!isObj(job)) return 'it can not be read';
  if (jobDeploys(job)) return job.environment !== undefined && job.environment !== null ? 'it has an environment' : 'it deploys';
  if (callsWorkflow(job)) return 'it calls another workflow';
  const text = JSON.stringify(job).replace(/\bsecrets\s*\.\s*GITHUB_TOKEN\b/gi, '');
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
  if (/\bvars\b/i.test(JSON.stringify(job))) return 'it reads a configuration variable (vars), which may be a deploy hook';
  return null;
}
