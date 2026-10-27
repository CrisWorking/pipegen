import { describe, expect, it } from 'vitest';
import type { PipelineDraft, RepoProfile } from '../src/types.js';
import { GATE_CHECK_NAME, NEED_CATEGORIES } from '../src/types.js';
import { emptyRepoFiles } from '../src/read/quality.js';

describe('types', () => {
  it('contracts compile', () => {
    const profile: RepoProfile = {
      owner: 'o', repo: 'x', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free',
      monorepo: 'none', services: [], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
    };
    const draft: PipelineDraft = {
      profile,
      capabilities: { branchProtection: false, environments: false, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false },
      needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [],
      requireDeployApproval: false, skipped: [], suggestions: [],
    };
    expect(draft.profile.repo).toBe('x');
    expect(GATE_CHECK_NAME).toBe('pipegen / gate');
    expect(NEED_CATEGORIES).toContain('gate');
  });
});
