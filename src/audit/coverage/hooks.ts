// Coverage mapper (see ../coverage.ts for the rules): git hooks (pre-commit, husky, lefthook) and CI `pre-commit run`.
import { regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { MAX_FLAG_WORDS, MAX_HITS, MAX_HOOKS } from './bounds.js';
import { HOOK_FILE } from './decide.js';
import { cut, firstSet, list, strs, workingDir } from './helpers.js';
import { resolveScripts } from './scripts.js';
import { commandReason, flagGiven, flagsAllow, foundOf, gateOf, gated } from './settings.js';
import { DEFAULT_SHELL, scanShell, type ShellMode } from './shell.js';
import { hookRepo, hookRepoKey } from './signatures.js';
import { tokenize, type Tk } from './tokenize.js';
import type { Ctx, Found, Hit, Manager, Obj, Reason } from './types.js';

// ---------- hooks ----------

export interface Hooks { manager: Manager | null; where: string; readable: boolean; found: Found[] }
/** husky runs a hook with `sh -e` (https://github.com/typicode/husky/blob/main/husky); lefthook runs each command
 *  with `sh -c`, without -e (internal/run/controller/exec/exec_unix.go). */
const HUSKY_SHELL: ShellMode = { errexit: true, pipefail: false };
const LEFTHOOK_SHELL: ShellMode = { errexit: false, pipefail: false };

/**
 * Task 5: a pre-commit `entry` (or a hook id) and its `args` as ONE command: pre-commit runs the entry without a
 * shell (https://pre-commit.com/#new-hooks), so `;`, `&&` or `|` in it are plain words, never a second command. The
 * words before the first operator are kept, up to the first word with a character outside [A-Za-z0-9_./:=@+,%-]
 * (a word with spaces or quotes, like `bash -c '…'`, isn't read into).
 */
function hookCommand(entry: string, args: readonly string[]): string {
  const out: string[] = [];
  for (const t of [...tokenize(entry), ...args.flatMap((a) => (regexSafe(a) ? [{ op: null, w: a, kw: null } as Tk] : []))]) {
    if (t.op !== null || !/^[A-Za-z0-9_./:=@+,%-]+$/.test(t.w) || out.length > MAX_FLAG_WORDS) break;
    out.push(t.w);
  }
  return out.join(' ');
}

/**
 * The tools `.pre-commit-config.yaml` runs. A hook runs before each commit when its `stages` (else `default_stages`)
 * include pre-commit or the legacy commit; one for another stage is kept with reason `stage`. Read once per call.
 * - `repo: local`: only the hook's `entry` runs; its id is just a name (Task 5). `repo: meta`: never counts.
 * - another repo: an `entry` set in the config replaces the hook's own; else a hook listed in tool-signatures.yml
 *   (`precommitHooks`: the exact repo URL and id) runs that tool, with the hook's `args` read for soft flags; else the
 *   id is read as a command (the hook's own entry isn't in this repo), with its args, as partial (`hook-repo`).
 * Fix round 1 (C2, I2): `meta` never counts; local `language: fail`/`pygrep` entries are a message or a regex, not a
 * command; a repo not listed in `precommitHooks` gives `hook-repo` (partial); any file filter gives `files`
 * (partial, never evaluated); another stage gives `stage` (partial). Not modelled: `always_run`, `fail_fast`.
 */
const NOT_A_COMMAND_LANGUAGES: ReadonlySet<string> = new Set(['fail', 'pygrep', 'script', 'unsupported_script', 'docker_image']);

/** Plan P Task 3 (PS14): the formatter hooks (signature ids) whose run in CI `pre-commit run --all-files` checks format. */
const FORMATTER_HOOKS: ReadonlySet<string> = new Set(['prettier', 'ruff-format', 'black', 'biome-format']);
/**
 * Whether a formatter hook run with these words fails `pre-commit run` on a file that isn't formatted: it rewrites the
 * file (pre-commit then fails the hook) or it checks and fails. prettier only prints without --write or a check flag
 * (https://github.com/prettier/prettier/blob/main/docs/cli.md); black and ruff format rewrite unless told otherwise,
 * and black's --diff alone only prints (https://github.com/psf/black/blob/main/docs/usage_and_configuration/the_basics.md);
 * biome format with --staged, --changed, --watch or --stdin-file-path doesn't format the files pre-commit passes.
 */
function formatterFails(by: string, words: readonly string[]): boolean {
  const has = (f: string) => flagGiven(f, words);
  if (by === 'prettier') return ['--write', '-w', '--check', '-c', '--list-different', '-l'].some(has);
  if (by === 'black') return !has('--diff') || has('--check');
  if (by === 'ruff-format') return !has('--stdin-filename');
  if (by === 'biome-format') return !['--staged', '--changed', '--watch', '--stdin-file-path'].some(has);
  return false;
}

function readPrecommitConfig(ctx: Ctx): Promise<{ readable: boolean; found: Found[] }> {
  ctx.precommitConfig ??= (async () => {
    const r = await ctx.read.yaml(HOOK_FILE['pre-commit']);
    if ('fail' in r) return { readable: r.fail === 'missing', found: [] };
    const defaultStages = strs(r.ok.default_stages);
    const isSet = (o: Obj, key: string) => key in o && o[key] !== null && o[key] !== undefined;
    const topFiltered = isSet(r.ok, 'files') || isSet(r.ok, 'exclude');
    const found: Found[] = [];
    const scan = (text: string) => scanShell(text, '.', ctx.sigs, ctx.budget, DEFAULT_SHELL);
    const tag = (fs: Found[], reason: Reason): Found[] => fs.map((f) => ({ ...f, reason: f.reason ?? reason }));
    for (const rawRepo of list(r.ok.repos).slice(0, MAX_HOOKS)) {
      const repo = asObj(rawRepo);
      const url = typeof repo.repo === 'string' && regexSafe(repo.repo) ? repo.repo : '';
      if (url === 'meta') continue; // pre-commit's own config checks; `entry` can't be set there
      const local = url === 'local';
      const known = !local && ctx.sigs.hookRepos.has(hookRepo(url));
      for (const raw of list(repo.hooks).slice(0, MAX_HOOKS)) {
        const hook = asObj(raw);
        const allArgs = strs(hook.args);
        const args = allArgs.slice(0, MAX_FLAG_WORDS);
        // Plan P Task 3: more args than pipegen reads may hide a soft flag past them
        const complete = allArgs.length <= MAX_FLAG_WORDS;
        const id = typeof hook.id === 'string' && regexSafe(hook.id) ? hook.id : '';
        const entry = typeof hook.entry === 'string' && regexSafe(hook.entry) ? hook.entry : undefined;
        let hookFound: Found[] = [];
        // the words the hook runs with, for the formatter rule (PS14): the entry and args, or the args of a known hook
        let words: string[] = [];
        if (local) {
          // `language: fail` prints its entry as a message and `pygrep` reads it as a regex; `script` and
          // `unsupported_script` run the entry as a file in the repo, and `docker_image` starts with an image name
          // (https://pre-commit.com/#supported-languages): none of them runs the named tool (fix round 2, N2)
          if (entry !== undefined && !(typeof hook.language === 'string' && NOT_A_COMMAND_LANGUAGES.has(hook.language))) {
            words = hookCommand(entry, args).split(' ');
            hookFound = scan(hookCommand(entry, args));
          }
        } else if (entry !== undefined) {
          words = hookCommand(entry, args).split(' ');
          hookFound = known ? scan(hookCommand(entry, args)) : tag(scan(hookCommand(entry, args)), 'hook-repo');
        } else if (id !== '') {
          const tools = known ? ctx.sigs.hooks.get(hookRepoKey(url, id)) : undefined;
          words = tools !== undefined ? args : hookCommand(id, args).split(' ');
          hookFound = tools !== undefined
            ? tools.filter((t) => flagsAllow(t, args, complete)).map((t) => foundOf(t, '.', commandReason(t, args) ?? (complete ? null : 'long')))
            : tag(scan(hookCommand(id, args)), 'hook-repo');
        }
        hookFound = hookFound.map((f) => (FORMATTER_HOOKS.has(f.by) ? { ...f, formats: formatterFails(f.by, words) } : f));
        // a file filter pipegen doesn't evaluate (they are Python regexes from the repo), or another stage
        const filtered = topFiltered || ['files', 'exclude', 'types', 'types_or', 'exclude_types'].some((k) => isSet(hook, k));
        if (filtered) hookFound = tag(hookFound, 'files');
        const stages = 'stages' in hook ? strs(hook.stages) : defaultStages;
        if (stages.length > 0 && !stages.some((st) => st === 'pre-commit' || st === 'commit')) hookFound = hookFound.map((f) => ({ ...f, reason: 'stage' }));
        found.push(...hookFound);
      }
    }
    return { readable: true, found: await resolveScripts(ctx, found) };
  })();
  return ctx.precommitConfig;
}

export async function readHooks(ctx: Ctx): Promise<Hooks> {
  const manager = ctx.p.precommit;
  const none: Hooks = { manager, where: '', readable: true, found: [] };
  if (manager === null) return none;
  const scan = async (text: string, base: string | null, mode: ShellMode) =>
    gated(await resolveScripts(ctx, scanShell(text, base, ctx.sigs, ctx.budget, mode)), gateOf([text], []));
  if (manager === 'husky') {
    const where = '.husky/pre-commit';
    const r = await ctx.read.text(where);
    if ('fail' in r) return { ...none, where: '.husky', readable: r.fail === 'missing' };
    return { manager, where, readable: true, found: await scan(r.ok, '.', HUSKY_SHELL) };
  }
  if (manager === 'pre-commit') {
    const config = await readPrecommitConfig(ctx);
    return { manager, where: HOOK_FILE['pre-commit'], readable: config.readable, found: config.found };
  }
  // lefthook: the first of lefthook.yml / lefthook.yaml that exists (readPrecommit's order)
  for (const where of ['lefthook.yml', 'lefthook.yaml']) {
    const r = await ctx.read.yaml(where);
    if ('fail' in r && r.fail === 'missing') continue;
    if ('fail' in r) return { ...none, where, readable: false };
    const hook = asObj(r.ok['pre-commit']);
    const entries = [...Object.values(asObj(hook.commands)), ...list(hook.jobs)].slice(0, MAX_HOOKS).map(asObj);
    const found: Found[] = [];
    for (const e of entries) if (typeof e.run === 'string') found.push(...(await scan(e.run, firstSet(workingDir(e.root)), LEFTHOOK_SHELL)));
    return { manager, where, readable: true, found };
  }
  return none;
}

/**
 * Task 5: a CI run of `pre-commit run --all-files` (hookRun) runs the hooks' lint tools there too. Only `lint` is
 * carried over: a secret-scan hook such as gitleaks' scans the staged changes (`--staged`, pass_filenames: false,
 * https://github.com/gitleaks/gitleaks/blob/master/.pre-commit-hooks.yaml), and a CI checkout has none staged. One run
 * per (trigger fit, reason) is enough (the first run of each kind is what a need reads), so this stays small.
 * Plan P Task 3: also the hooks' type-check, dockerfile-lint, workflow-lint and format categories; and a known
 * formatter hook (prettier, ruff-format, black, biome-format, matched by id or entry) counts for format without a
 * check flag, because pre-commit fails a hook that changes files ("files were modified by this hook",
 * https://github.com/pre-commit/pre-commit/blob/main/pre_commit/commands/run.py; ruling PS14). lefthook and husky
 * never carry anything here.
 */
const CARRIED: ReadonlySet<string> = new Set(['lint', 'type-check', 'dockerfile-lint', 'workflow-lint', 'format']);
/**
 * A formatter hook carries format when it writes files or checks them (formatterFails), or when a reason already keeps
 * it partial (a hook repo pipegen doesn't know, a file filter): it never makes the row covered then.
 */
const carried = (f: Found): string[] => {
  const out = f.categories.filter((c) => CARRIED.has(c));
  if (FORMATTER_HOOKS.has(f.by) && (f.formats === true || f.reason !== null) && !out.includes('format')) out.push('format');
  return out;
};
export async function hookRunHits(ctx: Ctx): Promise<void> {
  const reps = new Map<string, Hit>();
  for (const h of ctx.hits) {
    const key = `${h.fit.push ? 1 : 0}${h.fit.merge ? 1 : 0}${h.fit.deploy ? 1 : 0}\u0000${h.reason ?? ''}`;
    if (h.hookRun === true && !reps.has(key)) reps.set(key, h);
  }
  if (reps.size === 0) return;
  const tools = new Map<string, { f: Found; categories: string[] }>();
  for (const f of (await readPrecommitConfig(ctx)).found) {
    const key = `${f.by}\u0000${f.reason ?? ''}`;
    const categories = carried(f);
    // a hook set up for another stage doesn't run in `pre-commit run` (its default stage is pre-commit)
    if (categories.length > 0 && f.reason !== 'stage' && !tools.has(key)) tools.set(key, { f, categories });
  }
  for (const rep of reps.values()) {
    for (const { f: t, categories } of tools.values()) {
      if (ctx.hits.length >= MAX_HITS) {
        ctx.budget.truncated = true;
        return;
      }
      ctx.hits.push({
        opaque: false, categories, by: t.by, subject: `${t.subject} in the pre-commit hooks`, dir: '.', reason: rep.reason ?? t.reason,
        fit: rep.fit, where: cut(`${rep.where} → ${HOOK_FILE['pre-commit']}`),
      });
    }
  }
}
