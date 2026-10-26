import type { Language, RepoProfile, SupportLevel } from '../types.js';

const AUDIT_TODAY = 'You can run `pipegen audit` today.';

/** Display names for the fixed Language union (never a repo string). */
const LANGUAGE_NAMES: Record<Language, string> = {
  node: 'Node', python: 'Python', go: 'Go', java: 'Java', dotnet: '.NET', ruby: 'Ruby', php: 'PHP', other: 'This language',
};

/**
 * Decides whether the full run can handle this repo, or only `pipegen audit`.
 * The full run calls this before asking for consent and stops politely on `audit-only`.
 * Reasons are fixed sentences; the only variable part is a Language value from the fixed union, never a repo string.
 */
export function supportLevel(p: Pick<RepoProfile, 'monorepo' | 'services'>, milestone: 'v0.2' | 'v0.4'): { level: SupportLevel; reasons: string[] } {
  const reasons: string[] = [];

  if (p.services.length === 0) {
    reasons.push(`The repo has no service pipegen can run yet. ${AUDIT_TODAY}`);
    return { level: 'audit-only', reasons };
  }

  // Planned rule: Plan W refines what v0.4 accepts. For now v0.4 = Node and Python, monorepos and several services allowed.
  const supported: Language[] = milestone === 'v0.4' ? ['node', 'python'] : ['node'];
  const unsupported = [...new Set(p.services.map((s) => s.language))].filter((l) => !supported.includes(l));
  for (const language of unsupported) {
    // Only Python is planned (v0.4); other languages are never promised a milestone.
    reasons.push(language === 'python'
      ? `Python support arrives in v0.4. ${AUDIT_TODAY}`
      : `${LANGUAGE_NAMES[language]} is not supported yet. ${AUDIT_TODAY}`);
  }

  if (milestone === 'v0.2' && (p.monorepo !== 'none' || p.services.length > 1)) {
    reasons.push(`Monorepos and repos with several services arrive in v0.4. ${AUDIT_TODAY}`);
  }

  return { level: reasons.length === 0 ? 'full' : 'audit-only', reasons };
}
