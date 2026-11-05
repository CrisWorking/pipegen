// The hook-file judge (v0.2 Plan G, G1: ruling B4). A hook runs on the developer's machine at every commit, so the rule is the D0a append
// pattern held byte for byte: the user's text untouched, then exactly pipegen's reviewed block (hookFile, the builder Plan G writes with), and
// nothing else. pipegen never adds a hook repo URL with a rev (pre-commit) or a remote config (lefthook remotes/extends): that would run a tool
// nobody reviewed (#58). The manager must be the repository's own (or lefthook, set up new, when it has none); the user may skip the part.
import { HOOK_FILES, hookFile, type HookManager } from '../created-builders.js';
import type { CreatedCtx } from '../created-files.js';
import type { CreatedFile } from '../../types.js';
import { isObj, parseYaml } from '../yaml-parse.js';

const managerOf = (path: string): HookManager | undefined => (Object.keys(HOOK_FILES) as HookManager[]).find((m) => HOOK_FILES[m] === path);
/** A line of added pre-commit text that names a remote repo or a rev: `repo:` with any value but local, or `rev:` at all. */
const REMOTE_LINE_RE = /^\s*(?:-\s+)?(repo|rev)\s*:\s*(.*?)\s*(?:#.*)?$/;
const unquote = (v: string): string => v.replace(/^(['"])(.*)\1$/, '$2');

/** Added text that brings in a remote hook (the explicit refusal; the byte check below refuses it too). */
function remoteProblems(manager: HookManager, original: string, content: string): string[] {
  const out: string[] = [];
  const added = content.startsWith(original) ? content.slice(original.length) : content;
  if (manager === 'pre-commit') {
    for (const line of added.split('\n')) {
      const m = REMOTE_LINE_RE.exec(line);
      if (m !== null && (m[1] === 'rev' || unquote(m[2] ?? '') !== 'local')) { out.push('the file adds a remote hook repo (a repo URL or a rev); pipegen never adds one: it would run a hook tool nobody reviewed on the developer\'s machine'); break; }
    }
    // and on the parsed data: every repo the new file has beyond the user's is local and has no rev
    const before = parseYaml(original === '' ? 'repos: []\n' : original, 'strict');
    const after = parseYaml(content, 'strict');
    if ('parsed' in before && 'parsed' in after && Array.isArray(before.parsed.js.repos) && Array.isArray(after.parsed.js.repos)) {
      const extra = after.parsed.js.repos.slice(before.parsed.js.repos.length);
      if (out.length === 0 && extra.some((r) => !isObj(r) || r.repo !== 'local' || Object.hasOwn(r, 'rev'))) out.push('the file adds a remote hook repo (a repo URL or a rev); pipegen never adds one: it would run a hook tool nobody reviewed on the developer\'s machine');
    }
  }
  if (manager === 'lefthook' && /^\s*(?:remotes|extends|git_url)\s*:/m.test(added)) out.push('the file adds a remote hook config (remotes or extends); pipegen never adds one: it would run hooks nobody reviewed on the developer\'s machine');
  return out;
}

export function hooksJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  const manager = managerOf(file.path);
  if (manager === undefined) return ['this is not a hook manager file pipegen appends to'];
  const { draft } = ctx;
  const p = draft.profile;
  if (draft.skipped.some((s) => s.part === 'precommit')) return ['you skipped the pre-commit hooks (--skip precommit), so pipegen writes no hook file'];
  const original = file.edited?.original;
  if (typeof original !== 'string') return ['the edited marker with the original text is missing'];
  if (typeof file.content !== 'string') return ['the file has no text'];
  if (p.precommit === null) {
    if (manager !== 'lefthook') return [`the repository has no hook manager, so pipegen sets up only lefthook (the reviewed one), in ${HOOK_FILES.lefthook}, never ${file.path}`];
    if ((p.otherHookManagers ?? []).length > 0) return [`the repository uses another hook manager (${(p.otherHookManagers ?? []).join(', ')}), so pipegen adds none of its own`];
    if (original !== '') return ['no hook manager exists, but an original text was given'];
  } else {
    if (p.precommit !== manager) return [`the repository's hook manager is ${p.precommit}, so pipegen edits only ${HOOK_FILES[p.precommit]}, never ${file.path}`];
    // pre-commit and lefthook read a config that exists: an empty original would replace it (or, for lefthook, shadow one under another name)
    if (manager !== 'husky' && original.trim() === '') return [`the ${manager} config exists, but the original text given is empty: writing would replace or shadow the user's config`];
  }
  const out = [...remoteProblems(manager, original, file.content)];
  if (!file.content.startsWith(original)) out.push('the user\'s text was changed: pipegen only appends its hooks after it');
  // G1-R2 I4: a YAML hook config is exactly one document that parses strictly (a second document, or a broken one, would hide pipegen's hooks)
  if (manager !== 'husky') {
    const r = parseYaml(file.content, 'strict');
    if ('problems' in r) out.push(`the file does not parse as one strict YAML document (${r.problems.join('; ')}), so the manager would not read pipegen's hooks`);
  }
  const built = hookFile(manager, original, draft, ctx.reviewed);
  if ('note' in built) return [...out, built.note];
  if (file.content !== built.content) out.push('the file is not exactly what pipegen\'s builder writes (the user\'s bytes unchanged, then pipegen\'s reviewed hook block appended), so it is refused');
  return out;
}
