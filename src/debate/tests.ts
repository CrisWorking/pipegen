// What pipegen does about tests, per service (v0.2 Plan F Task 6; rulings B3, S19). Only projects WITHOUT tests are decided here;
// Keep/Switch for projects that have tests is Plan T.
//   skip (--skip tests)  -> none, with a note that the merge layer has no test protection (no NotProven: `draft.skipped` is Plan G's)
//   no tests             -> Plan D's starter-test creator. It is never given `isolatedTestJob` (that job is Plan G's, ruling D7-R7), so for now it
//                           returns no files and one not-proven note; the part `tests` is then not proven
//   has tests            -> keep
// Every sentence returned here is pipegen's own. The creator's `notes` (the first can be the AI's explanation) are never passed on, and the
// NotProven has no needId: `unit-tests` / `full-tests` are floor needs and Plan G's gate inputs refuse them in `not-proven` (S19).
import type { CodeBundle } from '../ai/redact.js';
import { createStarterTests } from '../create/tests.js';
import { STARTER_TESTS_NOT_ISOLATED } from '../create/test-rules.js';
import type { AiProvider, CreatedFile, NotProven, RepoProfile, Service, TestDecision } from '../types.js';
import type { StarterDeps } from '../create/tests.js';

export interface TestsDeps {
  ai: AiProvider;
  /** `--skip tests`. */
  skip: boolean;
  starter: StarterDeps;
  /** Test hook: the creator. */
  create?: typeof createStarterTests;
}

export interface TestsResult { decision: TestDecision; files: CreatedFile[]; notProven?: NotProven; note?: string }

export const TESTS_SKIPPED_NOTE = 'Tests were skipped (--skip tests), so nothing checks the tests of this service and the merge layer has no test protection.';
export const TESTS_KEPT_REASON = 'This service already has tests, so pipegen keeps them.';
export const TESTS_NOT_PROVEN_NOTE = `pipegen wrote no starter tests for this service: ${STARTER_TESTS_NOT_ISOLATED}, so its tests are not proven.`;
export const STARTER_TESTS_LOCK_IN_NOTE = "These starter tests describe how the app behaves today. They can lock in today's bugs, so review them.";

export async function decideTests(s: Service, p: RepoProfile, bundle: CodeBundle, deps: TestsDeps): Promise<TestsResult> {
  if (deps.skip) {
    return { decision: { service: s.name, reasons: [TESTS_SKIPPED_NOTE], choice: 'none' }, files: [], note: TESTS_SKIPPED_NOTE };
  }
  if (s.hasTests) {
    return { decision: { service: s.name, ...(s.testFramework === undefined ? {} : { current: s.testFramework }), reasons: [TESTS_KEPT_REASON], choice: 'keep' }, files: [] };
  }
  const create = deps.create ?? createStarterTests;
  // `isolatedTestJob` is Plan G's; it is never set here, whatever the caller's StarterDeps say.
  const { isolatedTestJob: _never, ...starter } = deps.starter;
  void _never;
  const plan = await create(s, p, bundle, deps.ai, starter);
  const files = [...plan.files, ...plan.configEdits];
  if (plan.files.length === 0) {
    return {
      decision: { service: s.name, reasons: [TESTS_NOT_PROVEN_NOTE], choice: 'none' }, files: [],
      notProven: { part: 'tests', reason: TESTS_NOT_PROVEN_NOTE, missingSecrets: [] }, note: TESTS_NOT_PROVEN_NOTE,
    };
  }
  return { decision: { service: s.name, proposed: plan.framework, reasons: [...plan.reasons], choice: 'none' }, files, note: STARTER_TESTS_LOCK_IN_NOTE };
}
