// The inputs of the gate step in mode `gate` (Plan C final review, fix round A, ruling 1), in one place: renderGateStep writes exactly
// gateStepInputs(draft) and the referee requires the file's gate step `with` to equal it, so no literal of the gate step has a source of its
// own (the final review's Important 1: a `skipped` literal the draft never gave turned a failed required check into a pass; a missing
// `service-roots` made the gate block every run). A leaf module apart from tool-flags.ts (which the gate bundles too).
//
// Every input comes from the draft:
//   - the expression inputs (`mode`, `jobs`, `block-from`, `github-token`, `fp-key`) are fixed;
//   - `job-list` is jobListLiteral(gateJobList(draft));
//   - `service-roots` is every service folder of draft.profile (always written: an empty list when there is none);
//   - `skipped` from draft.skipped (the parts skipped with --skip, as need ids: SKIPPED_PART_NEEDS), `not-proven` from draft.notProven;
//   - `block-from-recorded`, `policy` and `protected-paths` from draft.gateSettings.
// An input with nothing to say is not written. Every value is checked with the gate row of RENDERER_INPUTS (the schemas the gate parses
// with), and the floor rules the gate enforces are applied here too, so a draft the gate would refuse fails at render time (GateJobListError).
import { FLOOR_NEEDS, type PipelineDraft, type SkippablePart } from '../types.js';
import { gateJobList, GateJobListError, jobListLiteral, type GateJobListOptions } from './gate-job-list.js';
import { NEED_ID_CATEGORY } from './need-ids.js';
import { PIPEGEN_GATE_USES, rendererInputProblems } from './tool-flags.js';

/** The expression inputs of the gate step in mode gate: the same text in every pipeline. */
export const GATE_STEP_EXPRESSIONS: Readonly<Record<string, string>> = Object.freeze({
  mode: 'gate', jobs: '${{ toJSON(needs) }}', 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', 'github-token': '${{ secrets.GITHUB_TOKEN }}', 'fp-key': '${{ secrets.PIPEGEN_FP_KEY }}',
});
/** The gate step inputs whose value is a JSON literal (the referee compares them as parsed JSON; the others as text). */
export const GATE_JSON_INPUTS: ReadonlySet<string> = new Set(['job-list', 'not-proven', 'skipped', 'policy', 'protected-paths', 'service-roots']);

/**
 * The need ids a part skipped with `--skip` stands for, as the gate's `skipped` input lists them (a listed one is shown as skipped and never
 * blocks; a floor need that is skipped does not count as missing). Only `tests` skips checks the merge gate waits for: the test needs (the
 * floor's unit-tests and full-tests, and migration-check, a full-tests need). The other parts make no check of the gate (pre-commit hooks,
 * deploy, Slack, lock edits, the docker and compose files) or are Plan G's to map when it renders them. secrets, sast, deps and the gate
 * itself can never be skipped (the gate blocks on them), and no part maps to one.
 */
export const SKIPPED_PART_NEEDS: Readonly<Record<SkippablePart, readonly string[]>> = Object.freeze({
  tests: ['unit-tests', 'full-tests', 'migration-check'], precommit: [], docker: [], compose: [], deploy: [], locks: [], slack: [], 'test-migration': [],
});

const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const isFloorNeed = (needId: string): boolean => FLOOR.has(needId) || FLOOR.has((NEED_ID_CATEGORY as Readonly<Record<string, string>>)[needId] ?? '');
const unique = (xs: readonly string[]): string[] => [...new Set(xs)];

/** The service folders of the profile, each once, in its order (the repository root is `.`), for `service-roots`. */
export function serviceRootsOf(draft: PipelineDraft): string[] {
  return unique(draft.profile.services.map((s) => (s.path === '' ? '.' : s.path)));
}

/**
 * Every input of the gate step in mode `gate`, by name, for this draft (see the header). Throws GateJobListError when the job list can not be
 * made or a value would be refused by the gate (a floor need not proven, a bad date, a service folder that is not a plain relative folder).
 */
export function gateStepInputs(draft: PipelineDraft, opts: GateJobListOptions = {}): Record<string, string> {
  const filled: Record<string, string> = { mode: GATE_STEP_EXPRESSIONS.mode as string, jobs: GATE_STEP_EXPRESSIONS.jobs as string, 'job-list': jobListLiteral(gateJobList(draft, opts)) };
  const notProven = unique(draft.notProven.flatMap((n) => (typeof n.needId === 'string' ? [n.needId] : [])));
  const floor = notProven.filter(isFloorNeed);
  if (floor.length > 0) throw new GateJobListError(`The draft marks the floor check ${floor.join(', ')} as not proven, but a floor check is always required (the gate would block).`);
  if (notProven.length > 0) filled['not-proven'] = JSON.stringify(notProven);
  const skipped = unique(draft.skipped.flatMap((s) => SKIPPED_PART_NEEDS[s.part] ?? []));
  if (skipped.length > 0) filled.skipped = JSON.stringify(skipped);
  const settings = draft.gateSettings ?? {};
  if (settings.policy !== undefined) filled.policy = JSON.stringify({ block: settings.policy.block, warn: settings.policy.warn });
  if (settings.protectedPaths !== undefined && settings.protectedPaths.length > 0) filled['protected-paths'] = JSON.stringify(settings.protectedPaths);
  filled['service-roots'] = JSON.stringify(serviceRootsOf(draft));
  filled['block-from'] = GATE_STEP_EXPRESSIONS['block-from'] as string;
  if (settings.blockFromRecorded !== undefined) filled['block-from-recorded'] = settings.blockFromRecorded;
  filled['github-token'] = GATE_STEP_EXPRESSIONS['github-token'] as string;
  filled['fp-key'] = GATE_STEP_EXPRESSIONS['fp-key'] as string;
  // the gate parses each with the same schema (gate/src/settings.ts); a value it would refuse fails here, at render time
  const problems = rendererInputProblems(PIPEGEN_GATE_USES, filled, filled);
  if (problems.length > 0) throw new GateJobListError(`The draft gives the gate step a value the gate would refuse: ${problems[0] as string}.`);
  return filled;
}
