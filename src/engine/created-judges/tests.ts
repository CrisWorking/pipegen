// The starter-test judge (v0.2 Plan D, D7; preflight S9). Test files are new (the guard refuses an overwrite).
// First the D7-R7 switch: AI-written tests run only in Plan G's isolated starter-test job, so every starter-test file is refused unless the delivery
// inputs say that job exists (`isolatedTestJob: true`), with the producer's words (STARTER_TEST_FILE_NOT_ISOLATED). The validator below is defense in
// depth, not the boundary. Then the judge runs the SAME rules leaf the creator uses (src/create/test-rules.ts: a real parse and a tree walk), with:
//   - the service found by the file's path (the deepest service that holds it), which must be a Node service with npm (B2: that is where the
//     reviewed vitest can be added; Python starter tests are v0.4);
//   - the service's package.json `type` from the delivery inputs (`serviceTypes`); no package is importable at all, not even one the service
//     depends on (S9 amended in D7 round 3);
//   - at most 20 starter-test files per service in the batch, counted from the batch (`ctx.files`).
// What the creator delivers passes; one changed byte or rule gives an issue. Everything shown goes through the active vault.
import { MAX_TEST_FILES, STARTER_TEST_FILE_NOT_ISOLATED, starterOwner, starterTestFileProblems } from '../../create/test-rules.js';
import type { CreatedFile, Service } from '../../types.js';
import { activeSafeText } from '../../util/known-values.js';
import type { CreatedCtx } from '../created-files.js';

const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

export function starterTestsJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  if (ctx.inputs.isolatedTestJob !== true) return [STARTER_TEST_FILE_NOT_ISOLATED];
  if (typeof file.content !== 'string') return ['the test file is not text'];
  const roots = ctx.draft.profile.services.map((s) => rootPrefix(s.path));
  const owner = starterOwner(file.path, roots);
  if (owner === null) return [`${activeSafeText(file.path, 80)} is not a path starter tests may use`];
  const owners = ctx.draft.profile.services.filter((s) => rootPrefix(s.path) === owner.root);
  if (owners.length !== 1) return ['no single service has this folder, so pipegen can not tell which service the test is for'];
  const svc = owners[0] as Service;
  if (svc.language !== 'node') return ['starter tests are written for Node services in this version (Python comes in v0.4)'];
  if (svc.packageManager !== 'npm') return ['starter tests are written for npm services in this version (the reviewed Vitest is added through npm)'];
  const out = starterTestFileProblems(file.path, file.content, { roots, typeOf: (root) => ctx.inputs.serviceTypes?.[root] });
  const batch = (ctx.files ?? []).filter((f) => f.repo === file.repo && starterOwner(f.path, roots)?.root === owner.root).length;
  if (batch > MAX_TEST_FILES) out.push(`the batch has ${batch} test files for this service, and pipegen writes at most ${MAX_TEST_FILES}`);
  return out;
}
