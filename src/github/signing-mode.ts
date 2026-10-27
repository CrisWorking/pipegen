// How images are signed for this repo (spec §5 "Signing"). Pure: built from the profile and the probed capabilities.
// Plan A Task 6 re-exports this from src/github/capabilities.ts instead of writing it again (Plan B ruling B1).
import type { Capabilities, RepoProfile } from '../types.js';

export type SigningMode = 'keyless' | 'attest' | 'key-env' | 'none';

/**
 * public → keyless (public logs are fine); private + attestations (Enterprise) → GitHub artifact attestations;
 * private + environments → a cosign key kept in a protected environment; else → none, because a repo secret could be
 * read from any branch and the signature would prove little. `caps.environments` is probed (Plan A Task 6), and spike
 * S3 found environments on Free private repos too, so key-env can be the answer there (DECISIONS #86).
 */
export function signingMode(p: RepoProfile, caps: Capabilities): SigningMode {
  if (!p.private) return 'keyless';
  if (caps.attestations) return 'attest';
  if (caps.environments) return 'key-env';
  return 'none';
}
