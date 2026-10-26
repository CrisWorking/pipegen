import { describe, expect, it } from 'vitest';
import { signingMode } from '../src/github/signing-mode.js';
import type { Capabilities, RepoProfile } from '../src/types.js';

const profile = (over: Partial<RepoProfile>): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'Organization', plan: 'free',
  monorepo: 'none', services: [], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, ...over,
});

// The capability table from Plan A Task 6 (public, private free, private team, private enterprise).
const capsFor = (row: 'public' | 'free' | 'team' | 'enterprise'): Capabilities => ({
  branchProtection: row !== 'free', environments: row !== 'free', envRequiredReviewers: row === 'public' || row === 'enterprise',
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
});
