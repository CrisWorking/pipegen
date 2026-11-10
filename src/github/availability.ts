// Who can use GitHub's code-security features (Plan P ruling PS16; catalogue verification R4). `codeSecurityAvailable` serves the
// scorecard check (src/engine/needs.ts) and the coverage mapper's `availability` rule (src/audit/coverage/walk.ts).
// `dependencyReviewActionUsable` is the one stricter rule for dependency-review-action, shared by the debate's offers
// (src/debate/builder.ts) and the audit's pick (src/audit/choose.ts) so the two can't drift (PL-C0, ruling P-R1/P-R2): public
// repos only, never a private one, because pipegen can't prove Advanced Security is on. A leaf: it imports types only.
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
  return p.private === false || (p.ownerType === 'Organization' && caps?.codeScanning === true);
}

/** Whether pipegen may offer dependency-review-action: only on a repo known to be public (`private === false`); fail closed otherwise. */
export function dependencyReviewActionUsable(p: Pick<RepoProfile, 'private'>): boolean {
  return p?.private === false;
}
