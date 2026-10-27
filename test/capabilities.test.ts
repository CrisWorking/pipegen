// Plan A Task 6: what GitHub allows for a repo, found by probing (DECISIONS #77, #86), with the plan table only as
// the fallback when a probe can't tell — and never for what key-based signing rests on (fix round 1, R4: fail closed).
// Every call goes to a fake fetch.
import { describe, expect, it } from 'vitest';
import { capabilityTable, classifyProbe, probeCapabilities, signingMode, SIGNING_ENVIRONMENT } from '../src/github/capabilities.js';
import { signingMode as planBSigningMode } from '../src/github/signing-mode.js';
import { GitHubAccessError, makeOctokit } from '../src/github/client.js';
import { GitHubRateLimitError, newRateBudget } from '../src/engine/github-rate.js';
import type { Capabilities, Plan, RepoProfile } from '../src/types.js';
import { fakeFetch, type Reply, type Routes } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

const API = 'https://api.github.com';
const R = `${API}/repos/o/r`;
const RULESETS = `GET ${R}/rulesets`;
const ENVS = `GET ${R}/environments`;
const POLICIES = `GET ${R}/environments/pipegen-signing/deployment-branch-policies`;
const SCAN = `GET ${R}/code-scanning/analyses`;
const UPGRADE = 'Upgrade to GitHub Pro or make this repository public to enable this feature.';
const NOT_ENABLED = 'Code scanning is not enabled for this repository. Please enable code scanning in the repository settings.';
const POLICY_NOTE = "Couldn't prove deployment branch policies here; key-based signing is decided at `finish`.";
const ok: Reply = { body: [] };
const noEnvs: Reply = { body: { total_count: 0, environments: [] } };
const err = (status: number, message: string, headers: Record<string, string> = {}): Reply => ({ status, body: { message }, headers });
const clock = () => ({ budget: newRateBudget(), sleep: async () => {} });

/** GET /environments listing the signing environment with the given policy. */
const signingEnv = (policy: unknown = { protected_branches: false, custom_branch_policies: true }): Reply =>
  ({ body: { total_count: 2, environments: [{ name: 'other' }, { name: 'pipegen-signing', deployment_branch_policy: policy }] } });
/** GET …/deployment-branch-policies listing these branch (or tag) rules. */
const policies = (...list: { name: string; type?: string }[]): Reply => ({ body: { total_count: list.length, branch_policies: list } });
/** A private repo whose signing environment is proven: custom policies, exactly the default branch. */
const proven: Routes = { [ENVS]: signingEnv(), [POLICIES]: policies({ name: 'main', type: 'branch' }) };

const probe = async (routes: Routes, p: { private: boolean; plan: Plan; ownerType?: 'User' | 'Organization'; defaultBranch?: string }) => {
  const f = fakeFetch(routes);
  const gh = makeOctokit(fake.githubPat(), { fetch: f.fetch });
  const notes: string[] = [];
  const caps = await probeCapabilities(gh, 'o', 'r', { ownerType: 'Organization', defaultBranch: 'main', ...p }, notes, clock());
  return { caps, notes, calls: f.calls };
};
const profile = (over: Partial<RepoProfile>): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'Organization', plan: 'free',
  monorepo: 'none', services: [], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, ...over,
});
const ALL: Capabilities = { branchProtection: true, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true, attestations: true, codeScanning: true, keylessSigningAllowed: true };

describe('probeCapabilities', () => {
  it('probe: public repo → all true', async () => {
    const { caps, notes, calls } = await probe({ [RULESETS]: ok, [ENVS]: noEnvs, [SCAN]: err(404, 'no analysis found') }, { private: false, plan: 'free', ownerType: 'User' });
    expect(caps).toEqual(ALL);
    expect(notes).toEqual([]);
    expect(calls.every((c) => c.method === 'GET' && c.url.origin === API)).toBe(true);
    expect(calls.some((c) => c.url.pathname.includes('deployment-branch-policies'))).toBe(false);
  });

  it('probe: rulesets 403 upgrade message → branchProtection false', async () => {
    // the plan can't be read ('unknown'): the probe decides, not the plan name [Review Focus 4]
    for (const plan of ['unknown', 'free', 'pro'] as const) {
      const { caps, notes } = await probe({ [RULESETS]: err(403, UPGRADE), [ENVS]: ok, [SCAN]: err(403, NOT_ENABLED) }, { private: true, plan, ownerType: 'User' });
      expect(caps.branchProtection).toBe(false);
      expect(notes.some((n) => /rulesets|branch protection/i.test(n))).toBe(false);   // a clear answer, not a fallback
    }
  });

  it('probe: code scanning 403 on private team → codeScanning false', async () => {
    for (const message of ['Advanced Security must be enabled for this repository to use code scanning.', NOT_ENABLED]) {
      const { caps, notes } = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: err(403, message) }, { private: true, plan: 'team' });
      expect(caps.codeScanning).toBe(false);
      expect(notes.filter((n) => /code scanning/.test(n))).toEqual([]);
    }
    // enabled (an analysis list) → true
    const { caps } = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: { body: [{ id: 1 }] } }, { private: true, plan: 'team' });
    expect(caps.codeScanning).toBe(true);
  });

  it('probe: code scanning 404 "no analysis found" → available (spike S3, DECISIONS #77)', async () => {
    const { caps } = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: err(404, 'no analysis found') }, { private: true, plan: 'enterprise' });
    expect(caps.codeScanning).toBe(true);
  });

  it('probe: code scanning inconclusive → false on a private repo, true on a public one (GitHub policy), each with a note', async () => {
    for (const reply of [err(404, 'Not Found'), err(403, 'Resource not accessible by personal access token'), err(500, 'oops')]) {
      const priv = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: reply }, { private: true, plan: 'enterprise' });
      expect(priv.caps.codeScanning).toBe(false);
      expect(priv.notes).toContain("Couldn't check code scanning with this token; treated as not available.");
      const pub = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: reply }, { private: false, plan: 'free' });
      expect(pub.caps.codeScanning).toBe(true);
      expect(pub.notes).toEqual(["Couldn't check code scanning with this token; GitHub offers it on every public repo."]);
    }
  });

  it('probe: 403 "Resource not accessible by integration" or "by personal access token" → inconclusive, table used, note added', async () => {
    for (const message of ['Resource not accessible by integration', 'Resource not accessible by personal access token']) {
      const all403 = { [RULESETS]: err(403, message, { 'x-accepted-github-permissions': 'metadata=read' }), [ENVS]: err(403, message), [SCAN]: err(403, message) };
      // private team: the table gives branch protection; environments and code scanning fail closed; nothing proves the policies
      let r = await probe(all403, { private: true, plan: 'team' });
      expect(r.caps).toEqual({ branchProtection: true, environments: false, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false });
      expect(r.notes).toEqual([
        "Couldn't check branch protection with this token; used the plan table.",
        "Couldn't check environments with this token; treated as not available.",
        "Couldn't check code scanning with this token; treated as not available.",
        POLICY_NOTE,
      ]);
      // public: the table gives everything
      r = await probe(all403, { private: false, plan: 'unknown' });
      expect(r.caps).toEqual(ALL);
      expect(r.notes).toHaveLength(3);
    }
  });

  it('probe: only a 403 with "Upgrade" wording → not available', async () => {
    // other refusals and errors are inconclusive: the table decides (private pro: rulesets yes) and a note says so
    for (const reply of [err(403, 'Must have admin rights to Repository.'), err(404, 'Not Found'), err(500, 'oops'), err(422, 'Validation Failed')]) {
      const { caps, notes } = await probe({ [RULESETS]: reply, [ENVS]: ok, [SCAN]: err(403, NOT_ENABLED) }, { private: true, plan: 'pro', ownerType: 'User' });
      expect(caps.branchProtection).toBe(true);
      expect(notes[0]).toMatch(/^Couldn't check branch protection/);
    }
    // the same refusals on a free private repo fall back to "no"
    const { caps } = await probe({ [RULESETS]: err(403, 'Must have admin rights to Repository.'), [ENVS]: ok, [SCAN]: ok }, { private: true, plan: 'free', ownerType: 'User' });
    expect(caps.branchProtection).toBe(false);
    // and an "Upgrade" answer is believed even where the table would say yes
    const up = await probe({ [RULESETS]: err(403, UPGRADE), [ENVS]: err(403, UPGRADE), [SCAN]: ok }, { private: true, plan: 'team' });
    expect(up.caps).toMatchObject({ branchProtection: false, environments: false, deploymentBranchPolicies: false, envRequiredReviewers: false });
    expect(up.notes).toEqual([POLICY_NOTE]);
  });

  it('classifyProbe: 403/422 "Upgrade" or "billing plan" = unavailable; permission refusals and the rest = inconclusive', () => {
    const e = (status: number, message: string) => Object.assign(new Error(message), { status, response: { data: { message }, headers: {} } });
    expect(classifyProbe(e(403, UPGRADE))).toEqual({ result: 'unavailable' });
    expect(classifyProbe(e(422, 'Failed to create the environment protection rule. Please ensure the billing plan supports the required reviewers protection rule.'))).toEqual({ result: 'unavailable' });
    expect(classifyProbe(e(403, 'Resource not accessible by integration'))).toEqual({ result: 'inconclusive', why: 'permission' });
    expect(classifyProbe(e(403, 'Resource not accessible by personal access token'))).toEqual({ result: 'inconclusive', why: 'permission' });
    expect(classifyProbe(e(422, 'Validation Failed'))).toEqual({ result: 'inconclusive', why: 'other' });
    expect(classifyProbe(e(404, 'Upgrade'))).toEqual({ result: 'inconclusive', why: 'other' });   // only 403 and 422
    expect(classifyProbe(new Error('network'))).toEqual({ result: 'inconclusive', why: 'other' });
  });

  it('probe: Free private with a proven signing environment → key-env (DECISIONS #86, R4)', async () => {
    expect(SIGNING_ENVIRONMENT).toBe('pipegen-signing');
    const { caps, notes, calls } = await probe({ [RULESETS]: err(403, UPGRADE), ...proven, [SCAN]: err(403, NOT_ENABLED) }, { private: true, plan: 'free', ownerType: 'User' });
    expect(caps).toEqual({ branchProtection: false, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false });
    expect(notes).toEqual([]);
    expect(signingMode(profile({ plan: 'free', ownerType: 'User' }), caps)).toBe('key-env');
    expect(calls.every((c) => c.method === 'GET')).toBe(true);
    // the measured table (S3) still says Free private has environments, but the probe is what counts
    expect(capabilityTable({ private: true, plan: 'free', ownerType: 'User' }).environments).toBe(true);
  });

  it('probe: environments 200 with no policy → deploymentBranchPolicies false', async () => {
    const cases: Routes[] = [
      { [ENVS]: noEnvs },                                                                   // no signing environment yet
      { [ENVS]: signingEnv(null), [POLICIES]: policies({ name: 'main' }) },                 // any branch may deploy
      { [ENVS]: signingEnv({ protected_branches: true, custom_branch_policies: false }), [POLICIES]: policies({ name: 'main' }) },
      { [ENVS]: signingEnv(), [POLICIES]: policies() },                                     // custom, but no rule
      { [ENVS]: signingEnv(), [POLICIES]: policies({ name: 'main' }, { name: 'dev' }) },     // more than the default branch
      { [ENVS]: signingEnv(), [POLICIES]: policies({ name: 'release/*' }) },                // not the default branch
      { [ENVS]: signingEnv(), [POLICIES]: policies({ name: 'main', type: 'tag' }) },         // a tag rule, not a branch
      { [ENVS]: signingEnv(), [POLICIES]: err(403, 'Resource not accessible by personal access token') },
      { [ENVS]: signingEnv(), [POLICIES]: { body: { branch_policies: 'nope' } } },
    ];
    for (const routes of cases) {
      const { caps, notes } = await probe({ [RULESETS]: ok, [SCAN]: ok, ...routes }, { private: true, plan: 'team' });
      expect(caps.environments).toBe(true);
      expect(caps.deploymentBranchPolicies).toBe(false);
      expect(notes).toContain(POLICY_NOTE);
      expect(signingMode(profile({ plan: 'team' }), caps)).toBe('none');
    }
    // the default branch name comes from the profile
    const trunk = await probe({ [RULESETS]: ok, [SCAN]: ok, [ENVS]: signingEnv(), [POLICIES]: policies({ name: 'trunk' }) }, { private: true, plan: 'team', defaultBranch: 'trunk' });
    expect(trunk.caps.deploymentBranchPolicies).toBe(true);
  });

  it('probe: environments inconclusive → deploymentBranchPolicies false (fail closed)', async () => {
    for (const reply of [err(403, 'Resource not accessible by integration'), err(404, 'Not Found'), err(500, 'oops')]) {
      const { caps, notes, calls } = await probe({ [RULESETS]: ok, [SCAN]: ok, [ENVS]: reply, [POLICIES]: policies({ name: 'main' }) }, { private: true, plan: 'enterprise' });
      expect(caps.environments).toBe(false);
      expect(caps.deploymentBranchPolicies).toBe(false);
      expect(caps.envRequiredReviewers).toBe(false);
      expect(notes).toEqual(["Couldn't check environments with this token; treated as not available.", POLICY_NOTE]);
      expect(calls.some((c) => c.url.pathname.includes('deployment-branch-policies'))).toBe(false);
    }
  });

  it('probe: a rate limit stops the probe instead of falling back to the table', async () => {
    const limited = err(403, 'API rate limit exceeded', { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 3600) });
    await expect(probe({ [RULESETS]: limited, [ENVS]: ok, [SCAN]: ok }, { private: true, plan: 'free' })).rejects.toBeInstanceOf(GitHubRateLimitError);
    await expect(probe({ [RULESETS]: ok, [ENVS]: signingEnv(), [POLICIES]: limited, [SCAN]: ok }, { private: true, plan: 'free' })).rejects.toBeInstanceOf(GitHubRateLimitError);
  });

  it('probe: a 401 is a hard "token rejected" error', async () => {
    const e = await probe({ [RULESETS]: err(401, 'Bad credentials'), [ENVS]: ok, [SCAN]: ok }, { private: true, plan: 'free' }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect((e as Error).message).toMatch(/rejected the token/);
  });

  it('capabilityTable: the fallback table as built (S3 overrides the brief for Free private environments)', () => {
    const row = (p: boolean, plan: Plan, ownerType: 'User' | 'Organization' = 'Organization') => capabilityTable({ private: p, plan, ownerType });
    expect(row(false, 'free')).toEqual(ALL);
    const none = { branchProtection: false, environments: true, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false };
    expect(row(true, 'free', 'User')).toEqual(none);
    expect(row(true, 'unknown')).toEqual(none);
    expect(row(true, 'pro', 'User')).toEqual({ ...none, branchProtection: true });
    expect(row(true, 'team')).toEqual({ ...none, branchProtection: true });
    expect(row(true, 'enterprise')).toEqual({ ...none, branchProtection: true, envRequiredReviewers: true, attestations: true });
  });
});

describe('signingMode', () => {
  it('signingMode: public keyless; private enterprise attest; private team key-env; private free none', async () => {
    expect(signingMode).toBe(planBSigningMode);   // re-exported, not written again
    const pub = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: err(404, 'no analysis found') }, { private: false, plan: 'free' });
    expect(signingMode(profile({ private: false }), pub.caps)).toBe('keyless');
    const ent = await probe({ [RULESETS]: ok, [ENVS]: ok, [SCAN]: ok }, { private: true, plan: 'enterprise' });
    expect(signingMode(profile({ plan: 'enterprise' }), ent.caps)).toBe('attest');
    const team = await probe({ [RULESETS]: ok, ...proven, [SCAN]: ok }, { private: true, plan: 'team' });
    expect(signingMode(profile({ plan: 'team' }), team.caps)).toBe('key-env');
    // private free where GitHub refuses environments (an "Upgrade" answer) → none
    const free = await probe({ [RULESETS]: err(403, UPGRADE), [ENVS]: err(403, UPGRADE), [SCAN]: ok }, { private: true, plan: 'free', ownerType: 'User' });
    expect(signingMode(profile({ plan: 'free', ownerType: 'User' }), free.caps)).toBe('none');
  });
});
