// The registry of created-file kinds (v0.2 Plan D, D0a; preflight B1). A leaf: it imports only src/types.ts.
//
// The referee is the last check before delivery, so it judges or refuses EVERY file pipegen proposes. A file that is not a workflow
// or a composite action must match exactly one rule here; the rule's judge then decides. A path no rule claims is refused. The principle:
// a file pipegen computes is recomputed by its judge and compared byte for byte; a file an AI writes is judged by rules. Later
// sub-tasks (D0b judges, D1-D6 creators, Plan G's hook/central/record files) fill in or add their entries in this one place.
//
// The entries below that have no judge yet are STUBS: they claim their path and refuse, so a file of that kind can not pass
// unjudged while its sub-task is unbuilt. Replace the stub's judge with the real one; do not widen `match`.
//
// Each sub-task that fills in a judge also RE-CHECKS its matcher: a matcher claims only the files of its own kind and never a
// protected path or a tool config. No rule claims anything under `.github/`, `.husky/`, `.zap/` or `node_modules/`, or any path with a
// segment that starts with `.` (the exceptions: the CODEOWNERS and dependabot rules, which match only their exact paths, and
// `.dockerignore` at a service root, which is the one dot-name a Docker rule needs). A test probes every protected path and config name.
//
// Deliberately NO rule (B4, #108): biome/eslint/hadolint/c8/vitest/knip/prettier configs, `.gitleaksignore`, `.semgrepignore`,
// `.trivyignore`, `.prettierignore`, `lefthook.yml`, `.pre-commit-config.yaml`, `.husky/*`. Those are protected paths; a created copy
// could only shadow or weaken the pinned one. Plan G registers its hook, central and install-record files as it builds them.
import type { CreatedFile, Part, PipelineDraft } from '../types.js';
import { createdPathProblem } from './job-rules.js';

/** What a judge gets besides the file: the draft the files belong to. */
export interface CreatedCtx { draft: PipelineDraft }

export interface CreatedRule {
  id: string;
  repo: 'app' | 'central';
  /** The `part` a file of this kind carries. */
  parts: readonly Part[];
  /** Whether this rule claims the (already path-checked) path of a file of `repo`. Exactly one rule of that repo may claim a path. */
  match: (path: string, draft: PipelineDraft) => boolean;
  /** `new`: a file written whole (no `edited` marker). `edit`: a change to a file that may exist (the `edited` marker is required; its `original` is '' for a new file). */
  mode: 'new' | 'edit';
  /** The referee requires `CreatedFile.needsConfirm === true` (spec section 9: any change to scripts or dependencies). */
  needsConfirm?: true;
  /** The reasons the file is refused (empty: it passes). Never throws for anything in the file; a throw is an issue anyway. */
  judge: (file: CreatedFile, ctx: CreatedCtx) => string[];
}

/** A judge that refuses everything, for a kind whose sub-task is not built yet. */
const refuseUntilBuilt = (task: string) => (): string[] => [`the judge for this kind of file is not built yet (${task}), so pipegen can not prove it and does not write it`];

/** A service folder as a path prefix: '.' and './' are the repo root (''), a trailing '/' is dropped. */
const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
const serviceRoots = (draft: PipelineDraft): string[] => draft.profile.services.map((s) => rootPrefix(s.path));
/** A path with a hidden segment (`.x`) or a `node_modules` segment: no rule below claims one, bar the named exceptions. */
const hidden = (path: string): boolean => path.split('/').some((seg) => seg.startsWith('.') || seg === 'node_modules');
/** `<name>` exactly at the root of one of the draft's services (no deeper, no other service). */
const atServiceRoot = (path: string, draft: PipelineDraft, name: string): boolean => {
  if (path.slice(path.lastIndexOf('/') + 1) !== name) return false;
  const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
  return serviceRoots(draft).includes(dir);
};
const claimable = (path: string, draft: PipelineDraft, name: string): boolean => !hidden(path) && atServiceRoot(path, draft, name);
/** A test file: `<service>/(test|tests|__tests__)/…/<name>.test.<ext>` or `.spec.<ext>` with a code extension (D5, D7). */
const TEST_FILE_RE = /^(?:test|tests|__tests__)\/(?:[^/]+\/)*[^/]+\.(?:test|spec)\.(?:ts|js|mjs|cjs|tsx|jsx)$/;
const isStarterTest = (path: string, draft: PipelineDraft): boolean =>
  !hidden(path) && serviceRoots(draft).some((r) => (r === '' ? TEST_FILE_RE.test(path) : path.startsWith(`${r}/`) && TEST_FILE_RE.test(path.slice(r.length + 1))));

export const CREATED_RULES: readonly CreatedRule[] = [
  // D0b (CF-2): the judges for Plan G's files. Plan G produces them.
  { id: 'codeowners', repo: 'app', parts: ['codeowners'], mode: 'edit', match: (p) => p === 'CODEOWNERS' || p === 'docs/CODEOWNERS' || p === '.github/CODEOWNERS', judge: refuseUntilBuilt('D0b') },
  { id: 'codeowners-central', repo: 'central', parts: ['codeowners'], mode: 'edit', match: (p) => p === 'CODEOWNERS' || p === 'docs/CODEOWNERS' || p === '.github/CODEOWNERS', judge: refuseUntilBuilt('D0b') },
  { id: 'dependabot', repo: 'app', parts: ['pipeline', 'docs'], mode: 'edit', match: (p) => p === '.github/dependabot.yml' || p === '.github/dependabot.yaml', judge: refuseUntilBuilt('D0b') },
  { id: 'pipegen-doc', repo: 'app', parts: ['docs'], mode: 'new', match: (p) => p === 'PIPEGEN.md', judge: refuseUntilBuilt('D0b') },
  // D1-D4: the Docker files
  { id: 'dockerfile', repo: 'app', parts: ['docker'], mode: 'new', match: (p, d) => claimable(p, d, 'Dockerfile'), judge: refuseUntilBuilt('D3') },
  { id: 'dockerignore', repo: 'app', parts: ['docker'], mode: 'new', match: (p, d) => !p.split('/').slice(0, -1).some((x) => x.startsWith('.') || x === 'node_modules') && atServiceRoot(p, d, '.dockerignore'), judge: refuseUntilBuilt('D3') },
  { id: 'compose', repo: 'app', parts: ['compose'], mode: 'new', match: (p) => p === 'docker-compose.pipegen.yml', judge: refuseUntilBuilt('D4') },
  // D5-D7: starter tests, and the package edits (every package change needs the user's own yes)
  { id: 'starter-tests', repo: 'app', parts: ['tests'], mode: 'new', match: (p, d) => isStarterTest(p, d), judge: refuseUntilBuilt('D7') },
  { id: 'package-json', repo: 'app', parts: ['tests'], mode: 'edit', needsConfirm: true, match: (p, d) => claimable(p, d, 'package.json'), judge: refuseUntilBuilt('D6') },
  { id: 'package-lock', repo: 'app', parts: ['tests'], mode: 'edit', needsConfirm: true, match: (p, d) => claimable(p, d, 'package-lock.json'), judge: refuseUntilBuilt('D6') },
];

/** The verdict on one file: `claimed` false means no rule matched; `problems` are the reasons to refuse it. */
export function createdFileProblems(file: CreatedFile, draft: PipelineDraft, rules: readonly CreatedRule[] = CREATED_RULES): { claimed: boolean; problems: string[] } {
  // the path rule runs here, so no caller (the referee, the D1 guard, Plan G's deliver) can skip it; a matcher may claim a path it refuses
  const pathProblem = createdPathProblem(file.path);
  if (pathProblem !== null) return { claimed: true, problems: [`The file path is refused: ${pathProblem}; pipegen writes only plain, normalized paths.`] };
  let matching: CreatedRule[];
  try { matching = rules.filter((r) => r.repo === file.repo && r.match(file.path, draft)); } catch { return { claimed: true, problems: ['a rule for this kind of file failed to read the path'] }; }
  if (matching.length === 0) return { claimed: false, problems: [] };
  if (matching.length > 1) return { claimed: true, problems: [`more than one rule claims this path (${matching.map((r) => r.id).join(', ')}), so pipegen can not tell what the file is`] };
  const rule = matching[0] as CreatedRule;
  const problems: string[] = [];
  if (!rule.parts.includes(file.part)) problems.push(`this kind of file (${rule.id}) does not belong to the part ${JSON.stringify(file.part)}`);
  if (file.inserted !== undefined) problems.push('Only a workflow file can carry the mark of an edited user workflow.');
  const markOk = typeof file.edited === 'object' && file.edited !== null && typeof file.edited.original === 'string';
  if (file.edited !== undefined && !markOk) problems.push('the edited marker is malformed (it must be an object with the original text)');
  if (rule.mode === 'new' && file.edited !== undefined) problems.push(`this kind of file (${rule.id}) is written whole, not edited`);
  if (rule.mode === 'edit' && file.edited === undefined) problems.push(`this kind of file (${rule.id}) is an edit and needs the edited marker with the original text`);
  if (rule.needsConfirm === true && file.needsConfirm !== true) problems.push(`this kind of file (${rule.id}) changes scripts or dependencies, so it needs the user's own confirmation (needsConfirm) and has none`);
  try { problems.push(...rule.judge(file, { draft })); } catch { problems.push(`the judge for ${rule.id} failed on this file, so pipegen does not write it`); }
  return { claimed: true, problems };
}

/**
 * Two created files of one repo whose paths are equal ignoring letter case (a macOS or Windows checkout would merge them), or where one
 * is a folder holding the other (`a` and `a/b`: a git tree can not hold both): one issue per clash.
 */
export function duplicatePathProblems(files: readonly CreatedFile[]): { file: CreatedFile; message: string }[] {
  const seen = new Map<string, CreatedFile>();
  const out: { file: CreatedFile; message: string }[] = [];
  for (const f of files) {
    const key = `${f.repo}:${f.path.toLowerCase()}`;
    const first = seen.get(key);
    if (first === undefined) seen.set(key, f);
    else out.push({ file: f, message: `This path equals ${JSON.stringify(first.path)} ignoring letter case, and two created files may not share a path (a macOS or Windows checkout would merge them).` });
  }
  for (const f of files) {
    const segs = f.path.toLowerCase().split('/');
    for (let i = 1; i < segs.length; i++) {
      const other = seen.get(`${f.repo}:${segs.slice(0, i).join('/')}`);
      if (other !== undefined && other !== f) out.push({ file: f, message: `The folder of this path is the created file ${JSON.stringify(other.path)} (ignoring letter case), and a path can not be both a file and a folder.` });
    }
  }
  return out;
}
