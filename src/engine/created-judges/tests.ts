// The starter-test judge (v0.2 Plan D, D7; preflight S9). Test files are new (the guard refuses an overwrite). The judge runs the SAME rules leaf the
// creator uses (src/create/test-rules.ts: a real parse and a tree walk), with:
//   - the service found by the file's path (the deepest service that holds it), which must be a Node service with npm (B2: that is where the
//     reviewed vitest can be added; Python starter tests are v0.4);
//   - the service's own `dependencies` names from the delivery inputs (`serviceDeps`): a package import is allowed only from that list, so a
//     missing input refuses the import, never allows it;
//   - at most 20 starter-test files per service in the batch, counted from the batch (`ctx.files`).
// What the creator delivers passes; one changed byte or rule gives an issue. Everything shown goes through the active vault.
import { MAX_TEST_FILES, starterOwner, starterTestFileProblems } from '../../create/test-rules.js';
import type { CreatedFile, Service } from '../../types.js';
import { activeSafeText } from '../../util/known-values.js';
import type { CreatedCtx } from '../created-files.js';

const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

export function starterTestsJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  if (typeof file.content !== 'string') return ['the test file is not text'];
  const roots = ctx.draft.profile.services.map((s) => rootPrefix(s.path));
  const owner = starterOwner(file.path, roots);
  if (owner === null) return [`${activeSafeText(file.path, 80)} is not a path starter tests may use`];
  const owners = ctx.draft.profile.services.filter((s) => rootPrefix(s.path) === owner.root);
  if (owners.length !== 1) return ['no single service has this folder, so pipegen can not tell which service the test is for'];
  const svc = owners[0] as Service;
  if (svc.language !== 'node') return ['starter tests are written for Node services in this version (Python comes in v0.4)'];
  if (svc.packageManager !== 'npm') return ['starter tests are written for npm services in this version (the reviewed Vitest is added through npm)'];
  const out = starterTestFileProblems(file.path, file.content, { roots, depsOf: (root) => ctx.inputs.serviceDeps?.[root], typeOf: (root) => ctx.inputs.serviceTypes?.[root] });
  const batch = (ctx.files ?? []).filter((f) => f.repo === file.repo && starterOwner(f.path, roots)?.root === owner.root).length;
  if (batch > MAX_TEST_FILES) out.push(`the batch has ${batch} test files for this service, and pipegen writes at most ${MAX_TEST_FILES}`);
  return out;
}
