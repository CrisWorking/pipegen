// How images are signed for this repo (spec §5 "Signing"). Pure: built from the profile and the probed capabilities.
// Plan A Task 6 re-exports this from src/github/capabilities.ts instead of writing it again (Plan B ruling B1).
import type { Capabilities, RepoProfile } from '../types.js';

export type SigningMode = 'keyless' | 'attest' | 'key-env' | 'none';

/**
 * public → keyless (public logs are fine); private + attestations (Enterprise) → GitHub artifact attestations;
 * private + environments + PROVEN deployment branch policies → a cosign key kept in the `pipegen-signing` environment,
 * which only the default branch can use; else → none, because a key any branch can read would prove little.
 * Both capabilities are probed (Plan A Task 6). Spike S3 found environments and enforced branch policies on Free
 * private repos too, so key-env can be the answer there (DECISIONS #86). Fail closed (Task 6 fix round 1, R4): an
 * environment alone isn't enough; its default-branch-only rule must have been read back. Ruling G-SIGN1: `pipegen run`
 * (firstRunSigning) creates a new environment and its rule after consent, reads both back, and only then asks again.
 */
export function signingMode(p: RepoProfile, caps: Capabilities): SigningMode {
  if (!p.private) return 'keyless';
  if (caps.attestations) return 'attest';
  if (caps.environments && caps.deploymentBranchPolicies) return 'key-env';
  return 'none';
}
