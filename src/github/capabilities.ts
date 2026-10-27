// What GitHub allows for one repo (Plan A Task 6). Found by PROBING the repo, never from the plan name alone
// (DECISIONS #77, #86; spikes S1, S2, S3). The plan table below is a fallback only where that is safe, and never for
// what key-based signing rests on.
//
// Probe answers:
// - 2xx → available.
// - 403 or 422 whose message has "Upgrade" or "billing plan" wording → not available (S3: "Upgrade to GitHub Pro or
//   make this repository public…", "…ensure the billing plan supports the required reviewers protection rule.").
// - 403 "Resource not accessible by integration" / "…by personal access token" → inconclusive: the token lacks that
//   permission, which says nothing about the plan.
// - Code scanning (S3): 404 "no analysis found" → available (enabled, nothing uploaded yet); 403 "Code scanning is
//   not enabled…" or "Advanced Security must be enabled…" → not available (S3 maps these explicitly).
// - Anything else (another 403, 404, 422, 5xx, network) → inconclusive.
// - 401 → a hard "GitHub rejected the token" error. A rate limit stops the probe (GitHubRateLimitError is thrown).
//
// What an inconclusive probe becomes (fix round 1, R2/R4: fail closed where pipegen would rely on it):
// - branchProtection: the plan table, with a note "…used the plan table." (Plan G creates the rulesets and sees the
//   real answer.)
// - environments, code scanning on a PRIVATE repo: false, with a note "…treated as not available."
// - code scanning on a PUBLIC repo: true. This is GitHub policy, not a guess: code scanning is offered on every
//   public repo (controller ruling, fix round 1). The note says so.
// - deploymentBranchPolicies is never taken from a table: public → true (keyless signing doesn't use it); private →
//   true ONLY when GET /environments lists `pipegen-signing` with `deployment_branch_policy.custom_branch_policies:
//   true` AND GET …/environments/pipegen-signing/deployment-branch-policies lists exactly one rule, a branch rule for
//   the default branch. Anything else (no environment yet, another rule, a refusal) → false with the note
//   "Couldn't prove deployment branch policies here; key-based signing is decided at `finish`." Plan G `finish`
//   creates the environment and the rule, reads both back, and only then asks signingMode again.
//
// The plan table (what each plan allows; S3 overrides the brief where they differ, DECISIONS #77):
//
// |                          | public | private free / unknown | private pro | private team | private enterprise |
// |--------------------------|--------|------------------------|-------------|--------------|--------------------|
// | branchProtection         | ✓      | ✗                      | ✓           | ✓            | ✓                  |
// | environments             | ✓      | ✓ (S3, against docs)   | ✓           | ✓            | ✓                  |
// | deploymentBranchPolicies | ✓      | ✗ (only a read-back proves it)                                          |
// | envRequiredReviewers     | ✓      | ✗                      | ✗           | ✗            | ✓                  |
// | attestations             | ✓      | ✗                      | ✗           | ✗            | ✓ (org-owned)      |
// | codeScanning             | ✓      | ✗                      | ✗           | ✗ (add-on: probe) | ✗ (probe)     |
// | keylessSigningAllowed    | ✓      | ✗                      | ✗           | ✗            | ✗                  |
//
// envRequiredReviewers follows the table but is never true without environments. attestations and
// keylessSigningAllowed come from the table (S3: "Feature not available for user-owned private repositories";
// keyless signing writes to the public Sigstore log, so never for private repos).
import type { Octokit } from '@octokit/rest';
import type { Capabilities, RepoProfile } from '../types.js';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { checkRepoNames, clockOf, githubTokenRejected, isAnonymousClient } from './client.js';

/** Plan B Task 1's pure signingMode, re-exported (not written again). key-env needs environments AND proven deployment branch policies (DECISIONS #86, fix round 1 R4). */
export { signingMode, type SigningMode } from './signing-mode.js';

/** The environment that holds the signing key (design §5 "Signing"). */
export const SIGNING_ENVIRONMENT = 'pipegen-signing';

type ProfileBits = Pick<RepoProfile, 'private' | 'plan' | 'ownerType'>;

/** The plan table above. */
export function capabilityTable(p: ProfileBits): Capabilities {
  if (!p.private) {
    return { branchProtection: true, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true, attestations: true, codeScanning: true, keylessSigningAllowed: true };
  }
  const paid = p.plan === 'pro' || p.plan === 'team' || p.plan === 'enterprise';
  const enterprise = p.plan === 'enterprise';
  return {
    branchProtection: paid,
    environments: true,
    deploymentBranchPolicies: false,
    envRequiredReviewers: enterprise,
    attestations: enterprise && p.ownerType === 'Organization',
    codeScanning: false,
    keylessSigningAllowed: false,
  };
}

export type ProbeClass = { result: 'unavailable' } | { result: 'inconclusive'; why: 'permission' | 'other' };

const messageOf = (e: unknown): string => {
  const err = e as { message?: unknown; response?: { data?: { message?: unknown } } } | null;
  const m = err?.response?.data?.message ?? err?.message;
  return typeof m === 'string' ? m : '';
};
const statusOf = (e: unknown): number | undefined => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' ? s : undefined;
};

/** How to read a failed probe (the rules in the header). Plan G uses it for its write calls too (422 "billing plan"). */
export function classifyProbe(e: unknown): ProbeClass {
  const status = statusOf(e);
  const msg = messageOf(e);
  if ((status === 403 || status === 422) && /\bupgrade\b|billing plan/i.test(msg)) return { result: 'unavailable' };
  if (status === 403 && /resource not accessible by (?:integration|personal access token)/i.test(msg)) return { result: 'inconclusive', why: 'permission' };
  return { result: 'inconclusive', why: 'other' };
}

type Answer<T> = { ok: true; data: T } | { ok: false; settled?: boolean };

/**
 * One GET probe: its data, or a settled false, or nothing settled. Rate stops are thrown, and so is a 401 on a client
 * that sent a token (the token was rejected). On an anonymous client a 401 only means "needs a token": inconclusive.
 */
async function ask<T>(gh: Octokit, call: () => Promise<{ data: T }>, clock: RateClock, special?: (e: unknown) => boolean | undefined): Promise<Answer<T>> {
  try {
    return { ok: true, data: (await withRateLimit(call, clock)).data };
  } catch (e) {
    if (isRateStop(e)) throw e;
    if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    const s = special?.(e);
    if (s === true) return { ok: true, data: undefined as T };
    if (s === false) return { ok: false, settled: true };
    return { ok: false, settled: classifyProbe(e).result === 'unavailable' ? true : undefined };
  }
}
/** true / false when the probe settled it, undefined when it didn't. */
const verdict = (a: Answer<unknown>): boolean | undefined => (a.ok ? true : a.settled ? false : undefined);

const codeScanningAnswer = (e: unknown): boolean | undefined => {
  const status = statusOf(e);
  const msg = messageOf(e);
  if (status === 404 && /no analysis found/i.test(msg)) return true;
  if (status === 403 && /code scanning is not enabled|advanced security must be enabled/i.test(msg)) return false;
  return undefined;
};

/** Does GET /environments list the signing environment with custom deployment branch policies? */
function signingEnvIsCustom(data: unknown): boolean {
  const list = (data as { environments?: unknown } | null)?.environments;
  if (!Array.isArray(list)) return false;
  const env = (list as { name?: unknown; deployment_branch_policy?: { custom_branch_policies?: unknown } | null }[])
    .find((e) => e?.name === SIGNING_ENVIRONMENT);
  return env?.deployment_branch_policy?.custom_branch_policies === true;
}

/** Does the policy list hold exactly one rule, a branch rule for `branch`? */
function onlyDefaultBranch(data: unknown, branch: string): boolean {
  const list = (data as { branch_policies?: unknown } | null)?.branch_policies;
  if (!Array.isArray(list) || list.length !== 1) return false;
  const rule = list[0] as { name?: unknown; type?: unknown } | null;
  return rule?.name === branch && (rule.type === undefined || rule.type === 'branch');
}

/**
 * Probes rulesets, environments, the signing environment's branch rule and code scanning on owner/repo (read-only
 * GETs through `gh`, which only talks to api.github.com). `notes` gets one line per probe that couldn't settle its
 * answer (see the header for what each becomes). `p.defaultBranch` is the branch the signing rule must name.
 */
export async function probeCapabilities(gh: Octokit, owner: string, repo: string, p: ProfileBits & Pick<RepoProfile, 'defaultBranch'>, notes: string[] = [], clock: RateClock = clockOf(gh)): Promise<Capabilities> {
  checkRepoNames(owner, [repo]);
  const table = capabilityTable(p);
  const couldnt = (what: string, then: string) => notes.push(`Couldn't check ${what} with this token; ${then}.`);

  let branchProtection = verdict(await ask(gh, () => gh.rest.repos.getRepoRulesets({ owner, repo, per_page: 1 }), clock));
  if (branchProtection === undefined) {
    couldnt('branch protection', 'used the plan table');
    branchProtection = table.branchProtection;
  }

  const envs = await ask(gh, () => gh.rest.repos.getAllEnvironments({ owner, repo, per_page: 100 }), clock);
  let environments = verdict(envs);
  if (environments === undefined) {
    if (p.private) couldnt('environments', 'treated as not available');
    else couldnt('environments', 'used the plan table');
    environments = p.private ? false : table.environments;
  }

  const scan = await ask(gh, () => gh.rest.codeScanning.listRecentAnalyses({ owner, repo, per_page: 1 }), clock, codeScanningAnswer);
  let codeScanning = verdict(scan);
  if (codeScanning === undefined) {
    if (p.private) couldnt('code scanning', 'treated as not available');
    else couldnt('code scanning', 'GitHub offers it on every public repo');
    codeScanning = !p.private;
  }

  let deploymentBranchPolicies = !p.private;
  if (p.private) {
    if (environments && envs.ok && signingEnvIsCustom(envs.data)) {
      const rules = await ask(gh, () => gh.request('GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', {
        owner, repo, environment_name: SIGNING_ENVIRONMENT, per_page: 100,
      }), clock);
      deploymentBranchPolicies = rules.ok && onlyDefaultBranch(rules.data, p.defaultBranch);
    }
    if (!deploymentBranchPolicies) notes.push("Couldn't prove deployment branch policies here; key-based signing is decided at `finish`.");
  }

  return {
    branchProtection,
    environments,
    deploymentBranchPolicies,
    envRequiredReviewers: environments && table.envRequiredReviewers,
    attestations: table.attestations,
    codeScanning,
    keylessSigningAllowed: table.keylessSigningAllowed,
  };
}
