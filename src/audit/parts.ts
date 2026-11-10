// Plan P Task PL-A1: the six parts of the audit report. A need lands in exactly one part, by when its check runs.
import type { Need, NeedCategory } from '../types.js';

export type PartId = 1 | 2 | 3 | 4 | 5 | 6;

export const PART_TITLE: Readonly<Record<PartId, string>> = {
  1: 'On your computer',
  2: 'Every pull request',
  3: 'Before merge',
  4: 'Build and release',
  5: 'Deploy',
  6: 'Scheduled and repo settings',
};

// A Record over NeedCategory: a new category fails to compile until it is given a part.
const PART_OF_CATEGORY: Readonly<Record<NeedCategory, PartId>> = {
  hooks: 1,
  secrets: 2, sast: 2, deps: 2, lint: 2, 'format-lint': 2, format: 2, 'type-check': 2, 'unit-tests': 2, 'full-tests': 2,
  coverage: 2, 'dead-code': 2, duplication: 2, iac: 2, licences: 2, 'dockerfile-lint': 2, 'workflow-lint': 2, 'hooks-ci': 2,
  gate: 3, 'dependency-review': 3,
  'image-build': 4, 'image-scan': 4, sbom: 4, signing: 4, attestation: 4, publishing: 4,
  'deploy-verify': 5, dast: 5, 'api-dast': 5, egress: 5,
  scorecard: 6, 'update-config': 6, 'workflow-pin-check': 6, fuzzing: 6,
};

/** The part a need belongs to. A pre-commit need is always part 1. An unknown category (never from the AI schema) goes to part 2, so no row is dropped. */
export function partOf(need: Pick<Need, 'category' | 'layer'>): PartId {
  if (need.layer === 'pre-commit') return 1;
  return (PART_OF_CATEGORY as Record<string, PartId | undefined>)[need.category] ?? 2;
}
