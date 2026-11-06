// G7: the verify job as the referee now requires it (deploy-steps.ts): the gate's find-run step under its id, then the head check; for a
// published image also the digest step and the signature check (test/deploy-layer.test.ts builds those through assemble). Older fixtures of
// the edited-workflow rules use a profile that publishes no image, so their verify job is these two steps and a time limit above the wait.
import { FIND_RUN_STEP_ID, renderHeadCheckStep } from '../../src/engine/deploy-steps.js';
import type { RenderedStep } from '../../src/engine/job-rules.js';
import type { RepoProfile } from '../../src/types.js';

/** The find-run step with its id, and the head check of the default branch. */
export const verifyTail = (find: RenderedStep, branch = 'main'): RenderedStep[] => [{ ...find, id: FIND_RUN_STEP_ID }, renderHeadCheckStep(branch)];
/** The verify job's own limit in these fixtures: longer than find-run's default 30-minute wait (G40). */
export const VERIFY_LIMIT = 45;
/** The profile with no Dockerfile on any service: no image is published, so the verify job needs no digest step or signature check. */
export const noImages = (p: RepoProfile): RepoProfile => ({ ...p, services: p.services.map(({ dockerfile: _d, ...s }) => s) });
