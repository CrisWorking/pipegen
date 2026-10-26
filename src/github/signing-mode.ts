// How images are signed for this repo (spec §5 "Signing"). Pure: built from the profile and the probed capabilities.
// Plan A Task 6 re-exports this from src/github/capabilities.ts instead of writing it again (Plan B ruling B1).
import type { Capabilities, RepoProfile } from '../types.js';

export type SigningMode = 'keyless' | 'attest' | 'key-env' | 'none';

/**
 * public → keyless (public logs are fine); private + attestations (Enterprise) → GitHub artifact attestations;
 * private + environments (Pro/Team) → a cosign key kept in a protected environment; else (private Free) → none,
 * because a repo secret could be read from any branch and the signature would prove little.
 */
export function signingMode(p: RepoProfile, caps: Capabilities): SigningMode {
  if (!p.private) return 'keyless';
  if (caps.attestations) return 'attest';
  if (caps.environments) return 'key-env';
  return 'none';
}
