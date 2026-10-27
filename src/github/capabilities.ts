// What GitHub allows for one repo (Plan A Task 6). Found by PROBING the repo, never from the plan name alone
// (DECISIONS #77, #86; spikes S1, S2, S3). The plan table below is only the fallback when a probe can't tell.
//
// Probe answers:
// - 2xx → available.
// - 403 or 422 whose message has "Upgrade" or "billing plan" wording → not available (S3: "Upgrade to GitHub Pro or
//   make this repository public…", "…ensure the billing plan supports the required reviewers protection rule.").
// - 403 "Resource not accessible by integration" / "…by personal access token" → inconclusive: the token lacks that
//   permission, which says nothing about the plan. The table is used and a note says so.
// - Code scanning (S3): 404 "no analysis found" → available (enabled, nothing uploaded yet); 403 "Code scanning is
//   not enabled…" or "Advanced Security must be enabled…" → not available (S3 maps these explicitly).
// - Anything else (another 403, 404, 422, 5xx, network) → inconclusive, table, note.
// - A rate limit stops the probe (GitHubRateLimitError is thrown): the caller stops all GitHub work.
//
// Fallback table, as built (S3 overrides the brief where they differ, DECISIONS #77):
//
// |                       | public | private free / unknown | private pro | private team | private enterprise |
// |-----------------------|--------|------------------------|-------------|--------------|--------------------|
// | branchProtection      | ✓      | ✗                      | ✓           | ✓            | ✓                  |
// | environments          | ✓      | ✓ (S3, against docs)   | ✓           | ✓            | ✓                  |
// | envRequiredReviewers  | ✓      | ✗                      | ✗           | ✗            | ✓                  |
// | attestations          | ✓      | ✗                      | ✗           | ✗            | ✓ (org-owned)      |
// | codeScanning          | ✓      | ✗                      | ✗           | ✗ (add-on: probe) | ✗ (probe)     |
// | keylessSigningAllowed | ✓      | ✗                      | ✗           | ✗            | ✗                  |
//
// Probed: branchProtection (GET rulesets), environments (GET environments, needs Actions: read, S1), codeScanning
// (GET code-scanning/analyses). envRequiredReviewers follows the table but is never true without environments.
// attestations and keylessSigningAllowed come from the table (S3: "Feature not available for user-owned private
// repositories"; keyless signing writes to the public Sigstore log, so never for private repos).
import type { Octokit } from '@octokit/rest';
import type { Capabilities, RepoProfile } from '../types.js';
import { isRateStop, newRateBudget, withRateLimit, type RateClock } from '../engine/github-rate.js';

/** Plan B Task 1's pure signingMode, re-exported (not written again). With environments probed on Free private repos it can give key-env there (DECISIONS #86). */
export { signingMode, type SigningMode } from './signing-mode.js';

type ProfileBits = Pick<RepoProfile, 'private' | 'plan' | 'ownerType'>;

/** The fallback table above. */
export function capabilityTable(p: ProfileBits): Capabilities {
  if (!p.private) {
    return { branchProtection: true, environments: true, envRequiredReviewers: true, attestations: true, codeScanning: true, keylessSigningAllowed: true };
  }
  const paid = p.plan === 'pro' || p.plan === 'team' || p.plan === 'enterprise';
  const enterprise = p.plan === 'enterprise';
  return {
    branchProtection: paid,
    environments: true,
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

/** One probe: true/false when GitHub's answer settles it, undefined when it doesn't. Rate stops are thrown. */
async function ask(call: () => Promise<unknown>, clock: RateClock, special?: (e: unknown) => boolean | undefined): Promise<boolean | undefined> {
  try {
    await withRateLimit(call, clock);
    return true;
  } catch (e) {
    if (isRateStop(e)) throw e;
    const s = special?.(e);
    if (s !== undefined) return s;
    return classifyProbe(e).result === 'unavailable' ? false : undefined;
  }
}

const codeScanningAnswer = (e: unknown): boolean | undefined => {
  const status = statusOf(e);
  const msg = messageOf(e);
  if (status === 404 && /no analysis found/i.test(msg)) return true;
  if (status === 403 && /code scanning is not enabled|advanced security must be enabled/i.test(msg)) return false;
  return undefined;
};

/**
 * Probes rulesets, environments and code scanning on owner/repo (read-only GETs through `gh`, which only talks to
 * api.github.com). `notes` gets one line per inconclusive probe: "Couldn't check X with this token; used the plan table."
 */
export async function probeCapabilities(gh: Octokit, owner: string, repo: string, p: ProfileBits, notes: string[] = [], clock: RateClock = { budget: newRateBudget() }): Promise<Capabilities> {
  const table = capabilityTable(p);
  const settle = (answer: boolean | undefined, fallback: boolean, what: string): boolean => {
    if (answer !== undefined) return answer;
    notes.push(`Couldn't check ${what} with this token; used the plan table.`);
    return fallback;
  };

  const branchProtection = settle(await ask(() => gh.rest.repos.getRepoRulesets({ owner, repo, per_page: 1 }), clock), table.branchProtection, 'branch protection');
  const environments = settle(await ask(() => gh.rest.repos.getAllEnvironments({ owner, repo, per_page: 1 }), clock), table.environments, 'environments');
  const codeScanning = settle(await ask(() => gh.rest.codeScanning.listRecentAnalyses({ owner, repo, per_page: 1 }), clock, codeScanningAnswer), table.codeScanning, 'code scanning');

  return {
    branchProtection,
    environments,
    envRequiredReviewers: environments && table.envRequiredReviewers,
    attestations: table.attestations,
    codeScanning,
    keylessSigningAllowed: table.keylessSigningAllowed,
  };
}
