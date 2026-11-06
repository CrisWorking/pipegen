// Coverage mapper (G6, ruling G6-R2 spec I2 / sec M2): whether the user's own hook file already runs a secret scanner that keeps a key out
// of the COMMIT, so pipegen's pre-commit layer adds no second one (Plan J G-J1: a check the repo already has is not added again).
//
// It reads the hook file with Plan J's hook reading (the tool signatures of data/tool-signatures.yml, scanShell, flagsAllow and
// commandReason, as readHooks does) and credits only a scanner that runs at the pre-commit stage and can fail: a Found of category
// `secrets` with no reason (no soft flag, no `|| true`, no condition, no file filter, no other stage, a known hook repo). Sync and pure on
// the file text, so the builder and the referee's judge decide the same. Repository scripts are not followed (`npm run x`): a scanner
// behind one is not credited, so pipegen adds its own hook (a harmless duplicate, never a missing scan).
//   - husky: the script, read as `sh -e` reads it;
//   - pre-commit: each hook of `.pre-commit-config.yaml` at the commit stage (its `stages`, else `default_stages`), without a file filter; a
//     remote hook only as its repo defines it (no `language` or `entry` override, G6-R-sec2), a local one by its entry;
//   - lefthook: never (pipegen appends to lefthook only when the file has no `pre-commit` key at all, so there is nothing at that stage).
import { regexSafe } from '../read/limits.js';
import { asObj } from '../read/manifest.js';
import { isObj, parseYaml } from '../engine/yaml-parse.js';
import { MAX_HOOKS } from './coverage/bounds.js';
import { commandReason, flagsAllow, foundOf } from './coverage/settings.js';
import { DEFAULT_SHELL, scanShell, type ShellMode } from './coverage/shell.js';
import { compile, hookRepo, hookRepoKey, loadToolSignatures } from './coverage/signatures.js';
import type { Compiled, Found } from './coverage/types.js';

let compiled: Compiled | undefined;
const sigs = (): Compiled => (compiled ??= compile(loadToolSignatures()));
const HUSKY_SHELL: ShellMode = { errexit: true, pipefail: false };
/** pre-commit languages that don't run the entry as a command (hooks.ts NOT_A_COMMAND_LANGUAGES). */
const NOT_A_COMMAND: ReadonlySet<string> = new Set(['fail', 'pygrep', 'script', 'unsupported_script', 'docker_image']);
const FILTER_KEYS = ['files', 'exclude', 'types', 'types_or', 'exclude_types'] as const;
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const credits = (fs: readonly Found[]): boolean => fs.some((f) => f.reason === null && f.categories.includes('secrets'));
const atCommit = (stages: readonly string[]): boolean => stages.length === 0 || stages.some((s) => s === 'pre-commit' || s === 'commit');
const budget = () => ({ visits: 0, bytes: 0, truncated: false });

/** Whether the hook file `original` of `manager` already runs a secret scanner at the commit stage that can fail. */
export function existingSecretsHook(manager: 'pre-commit' | 'husky' | 'lefthook', original: string): boolean {
  if (typeof original !== 'string' || original === '' || !regexSafe(original.slice(0, 1_000_000))) return false;
  try {
    if (manager === 'husky') return credits(scanShell(original, '.', sigs(), budget(), HUSKY_SHELL));
    if (manager === 'lefthook') return false;
    const r = parseYaml(original, 'strict');
    if ('problems' in r || !isObj(r.parsed.js)) return false;
    const doc = r.parsed.js;
    if (FILTER_KEYS.some((k) => doc[k] !== undefined && doc[k] !== null)) return false;
    const defaults = strs(doc.default_stages);
    const s = sigs();
    for (const rawRepo of (Array.isArray(doc.repos) ? doc.repos : []).slice(0, MAX_HOOKS)) {
      const repo = asObj(rawRepo);
      const url = typeof repo.repo === 'string' ? repo.repo : '';
      if (url === 'meta') continue;
      const local = url === 'local';
      for (const raw of (Array.isArray(repo.hooks) ? repo.hooks : []).slice(0, MAX_HOOKS)) {
        const hook = asObj(raw);
        if (!atCommit('stages' in hook ? strs(hook.stages) : defaults)) continue;
        if (FILTER_KEYS.some((k) => hook[k] !== undefined && hook[k] !== null)) continue;
        const args = strs(hook.args);
        if (local) {
          // a local hook runs its entry as a command, unless its language reads it as something else
          const entry = typeof hook.entry === 'string' ? hook.entry : undefined;
          if (entry === undefined || typeof hook.language !== 'string' || NOT_A_COMMAND.has(hook.language)) continue;
          if (credits(scanShell([entry, ...args].join(' '), '.', s, budget(), DEFAULT_SHELL))) return true;
          continue;
        }
        // G6-R-sec2: a remote hook is credited from its signature only as the hook repo defines it: a `language` or `entry` of the
        // user's own overrides what it runs (`language: fail` prints the entry, `entry: "true"` runs nothing), so it gets no credit
        if ('language' in hook || 'entry' in hook || !s.hookRepos.has(hookRepo(url))) continue;
        const id = typeof hook.id === 'string' ? hook.id : '';
        const tools = s.hooks.get(hookRepoKey(url, id));
        if (tools?.some((t) => flagsAllow(t, args) && commandReason(t, args) === null && credits([foundOf(t, '.', null)]))) return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
