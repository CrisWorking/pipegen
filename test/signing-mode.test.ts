import { describe, expect, it } from 'vitest';
import { signingMode } from '../src/github/signing-mode.js';
import type { Capabilities, RepoProfile } from '../src/types.js';
import { emptyRepoFiles } from '../src/read/quality.js';

const profile = (over: Partial<RepoProfile>): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'Organization', plan: 'free',
  monorepo: 'none', services: [], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(), ...over,
});

// The capability table from Plan A Task 6 (public, private free, private team, private enterprise).
const capsFor = (row: 'public' | 'free' | 'team' | 'enterprise'): Capabilities => ({
  branchProtection: row !== 'free', environments: row !== 'free', deploymentBranchPolicies: row !== 'free', envRequiredReviewers: row === 'public' || row === 'enterprise',
  attestations: row === 'public' || row === 'enterprise', codeScanning: row === 'public', keylessSigningAllowed: row === 'public',
});

describe('signingMode', () => {
  it('signingMode: public keyless; private enterprise attest; private team key-env; private free none', () => {
    expect(signingMode(profile({ private: false, plan: 'free' }), capsFor('public'))).toBe('keyless');
    expect(signingMode(profile({ plan: 'enterprise' }), capsFor('enterprise'))).toBe('attest');
    expect(signingMode(profile({ plan: 'team' }), capsFor('team'))).toBe('key-env');
    expect(signingMode(profile({ plan: 'free' }), capsFor('free'))).toBe('none');
    // the capabilities decide, not the plan name (the plan can be 'unknown')
    expect(signingMode(profile({ plan: 'unknown' }), capsFor('team'))).toBe('key-env');
    expect(signingMode(profile({ plan: 'unknown' }), capsFor('free'))).toBe('none');
  });

  it('signingMode: private + environments without branch policies → none', () => {
    // key-env rests on a PROVEN default-branch-only rule on the signing environment (fix round 1, R4): fail closed
    for (const plan of ['free', 'team', 'unknown'] as const) {
      expect(signingMode(profile({ plan }), { ...capsFor('team'), deploymentBranchPolicies: false })).toBe('none');
      expect(signingMode(profile({ plan }), { ...capsFor('team'), environments: false, deploymentBranchPolicies: true })).toBe('none');
      expect(signingMode(profile({ plan }), capsFor('team'))).toBe('key-env');
    }
    // public and attest repos don't need it
    expect(signingMode(profile({ private: false }), { ...capsFor('public'), deploymentBranchPolicies: false })).toBe('keyless');
    expect(signingMode(profile({ plan: 'enterprise' }), { ...capsFor('enterprise'), deploymentBranchPolicies: false })).toBe('attest');
  });
});
