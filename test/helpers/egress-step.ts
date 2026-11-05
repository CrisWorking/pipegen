// G4-R1: the referee requires pipegen's egress step first in every job it writes (the backstop of E0d). Test files that hand-build jobs from
// renderer steps add it here, so what they judge is the job as pipegen writes it. A job whose first step already is an egress step is kept.
import { renderEgressStep } from '../../src/engine/egress.js';
import type { RenderedStep } from '../../src/engine/job-rules.js';

export const EGRESS_STEP: RenderedStep = renderEgressStep([], { dockerNetworks: false });
export const withEgress = <T extends { uses?: string }>(steps: readonly T[]): T[] =>
  (steps[0]?.uses?.startsWith('bullfrogsec/bullfrog@') === true ? [...steps] : [EGRESS_STEP as unknown as T, ...steps]);
