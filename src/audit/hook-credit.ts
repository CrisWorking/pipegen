// Coverage mapper (G6, rulings G6-R2 spec I2 / sec M2, G6-R-sec2, G6-R3 H1): whether the user's own hook file already runs a secret scan
// that keeps a key out of the COMMIT, so pipegen's pre-commit layer adds no second one (Plan J G-J1: a check the repo already has is not
// added again), and whether the audit may say the pre-commit secrets row is covered.
//
// The rule is the module's own: a harmless duplicate, never a missing scan. Only ONE form is credited, the canonical remote gitleaks hook
// as gitleaks publishes it (https://github.com/gitleaks/gitleaks/blob/master/.pre-commit-hooks.yaml: `gitleaks git --pre-commit --redact
// --staged --verbose`, language golang, pass_filenames false):
//   - the official repo (or its old zricethezav URL, which redirects to it), at a v8+ release tag (never a bare commit sha, G6-R-sec3);
//   - id `gitleaks`, with no `entry`, `language` or `args` of the user's (pre-commit runs shlex.split(entry) + args with no shell, so a
//     `#`, a newline or `--exit-code=0` there is a real word, review H1 a), `pass_filenames` not true (gitleaks then reads a one-file
//     commit's file name as its repo path, H1 b), no file filter and no key pipegen doesn't read;
//   - at the commit stage: its `stages`, else (absent or empty, N2) `default_stages`, else every stage; and installed at pre-commit.
// Never credited: a local pre-commit hook (any entry, H1 a/c), husky (git may run it without -e, N1) and lefthook: pipegen adds its own
// hook there. trufflehog has no hook signature in data/tool-signatures.yml, so it is never credited either. Sync and pure on the text,
// so the builder and the referee's judge decide the same.
import { regexSafe } from '../read/limits.js';
import { asObj } from '../read/manifest.js';
import { isObj, parseYaml } from '../engine/yaml-parse.js';
import { MAX_HOOKS } from './coverage/bounds.js';

type Obj = Record<string, unknown>;
const GITLEAKS_REPOS: ReadonlySet<string> = new Set(['https://github.com/gitleaks/gitleaks', 'https://github.com/zricethezav/gitleaks']);
/**
 * A gitleaks v8+ release tag (v8 is the first whose hook reads only the staged changes). G6-R-sec3: never a bare commit sha: GitHub
 * serves a commit of any fork in the network through the upstream URL, so a sha may be one never released (a hook that does nothing).
 */
const PINNED_REV = /^v(?:[89]|[1-9]\d)\.\d{1,4}\.\d{1,4}$/;
/** The hook keys that don't change what the canonical hook runs or which files it sees. */
const COSMETIC_KEYS: ReadonlySet<string> = new Set(['id', 'name', 'alias', 'description', 'stages', 'verbose', 'log_file', 'require_serial', 'always_run', 'fail_fast', 'pass_filenames']);
const TOP_FILTER_KEYS = ['files', 'exclude'] as const;
const AT_COMMIT = (s: unknown) => s === 'pre-commit' || s === 'commit';
const ALL_STAGES = ['pre-commit'];
const normRepo = (repo: string) => repo.trim().toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
const isSet = (o: Obj, key: string) => o[key] !== undefined && o[key] !== null;

/** The stages a hook runs at, as pre-commit reads them; null when they are not a list of names. */
function stagesOf(doc: Obj, hook: Obj): readonly unknown[] | null {
  if (isSet(hook, 'stages')) {
    if (!Array.isArray(hook.stages)) return null;
    if (hook.stages.length > 0) return hook.stages;
  } else if ('stages' in hook) return null;
  if (!('default_stages' in doc)) return ALL_STAGES;
  return Array.isArray(doc.default_stages) ? doc.default_stages : null;
}

/**
 * Whether hook `hook` of repo entry `repo` in pre-commit config `doc` is the canonical gitleaks hook at the commit stage. Shared by the
 * pre-commit layer (existingSecretsHook) and the audit's hook reading (coverage/hooks.ts), so both credit exactly the same form.
 */
export function canonicalSecretsHook(doc: Obj, repo: Obj, hook: Obj): boolean {
  if (TOP_FILTER_KEYS.some((k) => isSet(doc, k))) return false;
  if (isSet(doc, 'default_install_hook_types') && !(Array.isArray(doc.default_install_hook_types) && doc.default_install_hook_types.includes('pre-commit'))) return false;
  if (typeof repo.repo !== 'string' || !GITLEAKS_REPOS.has(normRepo(repo.repo))) return false;
  if (typeof repo.rev !== 'string' || !PINNED_REV.test(repo.rev.trim())) return false;
  if (hook.id !== 'gitleaks' || Object.keys(hook).some((k) => !COSMETIC_KEYS.has(k))) return false;
  if ('pass_filenames' in hook && hook.pass_filenames !== false) return false;
  const stages = stagesOf(doc, hook);
  return stages !== null && stages.some(AT_COMMIT);
}

/** Whether the hook file `original` of `manager` already runs the canonical secret scan at the commit stage. */
export function existingSecretsHook(manager: 'pre-commit' | 'husky' | 'lefthook', original: string): boolean {
  if (manager !== 'pre-commit' || typeof original !== 'string' || original === '' || !regexSafe(original.slice(0, 1_000_000))) return false;
  try {
    const r = parseYaml(original, 'strict');
    if ('problems' in r || !isObj(r.parsed.js)) return false;
    const doc = r.parsed.js;
    for (const rawRepo of (Array.isArray(doc.repos) ? doc.repos : []).slice(0, MAX_HOOKS)) {
      const repo = asObj(rawRepo);
      for (const raw of (Array.isArray(repo.hooks) ? repo.hooks : []).slice(0, MAX_HOOKS)) if (canonicalSecretsHook(doc, repo, asObj(raw))) return true;
    }
    return false;
  } catch {
    return false;
  }
}
