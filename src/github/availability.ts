// Who can use GitHub's code-security features (Plan P ruling PS16; catalogue verification R4). One helper for the
// scorecard check (src/engine/needs.ts), the coverage mapper's `availability` rule (src/audit/coverage/walk.ts) and the
// dependency-review pick (Plan P Task 8). A leaf: it imports types only.
//
// - Public repos have code scanning and dependency review for free.
// - A private repo has them only when it is organisation-owned and the organisation has GitHub Advanced Security
//   (seen as `caps.codeScanning`). A user-owned private repo can't use dependency-review-action at all, whatever the
//   plan (https://github.com/actions/dependency-review-action/blob/main/README.md: "any public repository, or any
//   organization-owned private repository, provided the organization has a GitHub Advanced Security license").
// Visibility and owner type always come from the profile; without capabilities, code scanning counts as off.
import type { Capabilities, RepoProfile } from '../types.js';

/** Whether the repo can use code scanning and dependency review: public, or organisation-owned private with code scanning. */
export function codeSecurityAvailable(p: Pick<RepoProfile, 'private' | 'ownerType'>, caps?: Pick<Capabilities, 'codeScanning'>): boolean {
  return !p.private || (p.ownerType === 'Organization' && caps?.codeScanning === true);
}
