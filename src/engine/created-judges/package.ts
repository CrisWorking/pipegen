// The package.json and package-lock.json judges (v0.2 Plan D, D6; ruling B2). Both files are edits (`edited.original` is set by pipegen's own
// code); the registry rule makes them need the user's confirmation. The same functions the guard calls decide:
//   package.json       packageJsonProblems (the semantic diff) AND the exact text: the original with only the B2 entries and scripts.test
//                      inserted, rebuilt by buildPackageJson, must equal the content byte for byte;
//   package-lock.json  lockProblems against the reviewed closure, with the new package.json of the same folder (it must be in the batch).
// Both need an npm service (S13). Everything shown goes through the active vault (show / activeSafeText).
import { isDeepStrictEqual } from 'node:util';
import { buildPackageJson, editOf } from '../../create/package-edit.js';
import { lockProblems, packageJsonProblems, parseJsonStrict } from '../../create/package-rules.js';
import { loadReviewedClosure, type ReviewedClosure } from '../../create/reviewed-closure.js';
import type { CreatedFile, ReviewedTool } from '../../types.js';
import { activeSafeText } from '../../util/known-values.js';
import type { CreatedCtx } from '../created-files.js';

const MAX_LOCK_BYTES = 8 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 1024 * 1024;

const closures = new WeakMap<readonly ReviewedTool[], ReviewedClosure | null>();
/** The reviewed closure for a reviewed list (loaded once per list). */
export function closureFor(reviewed: readonly ReviewedTool[]): ReviewedClosure | null {
  if (!closures.has(reviewed)) closures.set(reviewed, loadReviewedClosure(reviewed));
  return closures.get(reviewed) ?? null;
}

const dirOf = (path: string): string => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
const rootPrefix = (p: string): string => p.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

/** The common checks of both files: an edit with its original, in an npm service. */
function common(file: CreatedFile, ctx: CreatedCtx, name: string): string | null {
  const original = file.edited?.original;
  if (typeof original !== 'string' || original === '') return `${name} is an edit of an existing file, and the original text is missing`;
  if (typeof file.content !== 'string') return `${name} has no content`;
  const dir = dirOf(file.path);
  const svc = ctx.draft.profile.services.find((s) => rootPrefix(s.path) === dir);
  if (svc === undefined || svc.packageManager !== 'npm') return `the service of ${activeSafeText(file.path, 80)} is not an npm service, and pipegen edits only npm packages in this version`;
  return null;
}

export function packageJsonJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  const bad = common(file, ctx, 'package.json');
  if (bad !== null) return [bad];
  const original = (file.edited as { original: string }).original;
  if (original.length > MAX_PACKAGE_BYTES || file.content.length > MAX_PACKAGE_BYTES) return ['package.json is too large to judge'];
  const out = packageJsonProblems(original, file.content);
  if (out.length > 0) return out;
  // the exact text: the original bytes with only the reviewed entries and scripts.test inserted
  let o: unknown;
  let n: unknown;
  try { o = parseJsonStrict(original); n = parseJsonStrict(file.content); } catch { return ['package.json can not be read as plain JSON']; }
  const expected = buildPackageJson(original, editOf(o as Record<string, unknown>, n as Record<string, unknown>));
  if (expected === null) return ['package.json has a shape pipegen can not rebuild from the original, so the edit can not be proven'];
  if (expected !== file.content) return ['package.json is not the original text with only the reviewed devDependencies and scripts.test inserted (something else differs, such as spacing, order or another byte)'];
  if (isDeepStrictEqual(o, n)) return ['package.json does not change anything'];
  return [];
}

export function packageLockJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  const bad = common(file, ctx, 'package-lock.json');
  if (bad !== null) return [bad];
  const original = (file.edited as { original: string }).original;
  if (original.length > MAX_LOCK_BYTES || file.content.length > MAX_LOCK_BYTES) return ['package-lock.json is over 8 MiB, so it is not judged and not written'];
  const dir = dirOf(file.path);
  const siblingPath = dir === '' ? 'package.json' : `${dir}/package.json`;
  const pkg = (ctx.files ?? []).find((f) => f.repo === file.repo && f.path === siblingPath);
  if (pkg === undefined) return [`package-lock.json is edited together with ${activeSafeText(siblingPath, 80)} in the same batch, and that file is not part of it`];
  return lockProblems(original, file.content, { packageJson: pkg.content, closure: closureFor(ctx.reviewed) });
}
