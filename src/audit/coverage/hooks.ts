// Coverage mapper (see ../coverage.ts for the rules): git hooks (pre-commit, husky, lefthook) and CI `pre-commit run`.
import { parse as parseToml } from 'smol-toml';
import { regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { MAX_FLAG_WORDS, MAX_HITS, MAX_HOOKS } from './bounds.js';
import { HOOK_FILE } from './decide.js';
import { cut, firstSet, list, strs, workingDir } from './helpers.js';
import { resolveScripts } from './scripts.js';
import { MAY_NOT_RUN, UNKNOWN_PREFIX, commandReason, configWhy, flagGiven, flagsAllow, foundOf, gateOf, gated, softEnvSet } from './settings.js';
import { DEFAULT_SHELL, scanShell, type ShellMode } from './shell.js';
import { PREK_ID, hookRepo, hookRepoKey } from './signatures.js';
import { tokenize, type Tk } from './tokenize.js';
import type { Ctx, Found, Hit, Manager, Obj, Reason } from './types.js';

// ---------- hooks ----------

export interface Hooks {
  manager: Manager | null; where: string; readable: boolean; found: Found[];
  /**
   * J3a (ruling B4): the hooks of the config pipegen can't say what they run: a hook from a repo it doesn't know, one
   * that runs something it doesn't recognise (a script that calls no known tool, an entry it can't read, a hook
   * `language` that doesn't run a command), or hooks past MAX_HOOKS. Labels are hook ids that are plain words, else a
   * fixed phrase. Read for the pre-commit framework only; husky and lefthook run free shell, so it is always [] there
   * and creditEquivalents never credits them.
   */
  unrecognised: string[];
}
/** What hookConfigRuns read: the tools the config runs and the hooks it couldn't place. */
interface HookConfig { found: Found[]; unrecognised: string[] }
const PLAIN_HOOK_ID = /^[A-Za-z0-9._-]{1,60}$/;
const MAX_UNRECOGNISED = 20;
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
  return hookWords(entry, args).text;
}
/**
 * P57 (fail closed): the same, and whether every word was read. A word pipegen doesn't read (spaces, quotes, an
 * operator, past MAX_FLAG_WORDS) ends the command early, and a soft flag after it would be missed: `complete` false
 * makes the hook's runs partial ('long'), never covered.
 */
function hookWords(entry: string, args: readonly string[]): { text: string; complete: boolean } {
  const out: string[] = [];
  const all = [...tokenize(entry), ...args.map((a) => (regexSafe(a) ? { op: null, w: a, kw: null } as Tk : { op: null, w: '\u0000', kw: null } as Tk))];
  for (const t of all) {
    if (t.op !== null || !/^[A-Za-z0-9_./:=@+,%-]+$/.test(t.w) || out.length > MAX_FLAG_WORDS) return { text: out.join(' '), complete: false };
    out.push(t.w);
  }
  return { text: out.join(' '), complete: true };
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

function readPrecommitConfig(ctx: Ctx): Promise<{ readable: boolean } & HookConfig> {
  ctx.precommitConfig ??= (async () => {
    const r = await ctx.read.yaml(HOOK_FILE['pre-commit']);
    if ('fail' in r) return { readable: r.fail === 'missing', found: [], unrecognised: [] };
    return { readable: true, ...(await hookConfigRuns(ctx, r.ok)) };
  })();
  return ctx.precommitConfig;
}

/**
 * P57 (C4): prek reads prek.toml before .pre-commit-config.yaml ("the first in the order above" wins,
 * https://github.com/j178/prek docs/configuration.md): when it exists, a CI prek run runs its hooks, read with the same
 * rules (its keys are the YAML's). 'unreadable' (a symbolic link, too large, not valid TOML): pipegen can't tell which
 * hooks run, and never credits the YAML's.
 */
function readPrekConfig(ctx: Ctx): Promise<'absent' | 'unreadable' | Found[]> {
  ctx.prekConfig ??= (async () => {
    const t = await ctx.read.text('prek.toml');
    if ('fail' in t) return t.fail === 'missing' ? 'absent' : 'unreadable';
    let doc: unknown;
    try {
      doc = parseToml(t.ok);
    } catch {
      return 'unreadable';
    }
    return (await hookConfigRuns(ctx, asObj(doc))).found;
  })();
  return ctx.prekConfig;
}

/** The tools a pre-commit config (`.pre-commit-config.yaml`, or prek.toml with the same keys) runs. */
async function hookConfigRuns(ctx: Ctx, config: Obj): Promise<HookConfig> {
  {
    const r = { ok: config };
    const defaultStages = strs(r.ok.default_stages);
    const isSet = (o: Obj, key: string) => key in o && o[key] !== null && o[key] !== undefined;
    const topFiltered = isSet(r.ok, 'files') || isSet(r.ok, 'exclude');
    const found: Found[] = [];
    const unrecognised: string[] = [];
    const scan = (text: string) => scanShell(text, '.', ctx.sigs, ctx.budget, DEFAULT_SHELL);
    // P57 (C1): a hook from a repo pipegen doesn't know may run anything, in any language: its id says nothing about which
    // P57 (fail closed): hooks past MAX_HOOKS aren't read, so what they run is unknown, never missing
    if (list(r.ok.repos).length > MAX_HOOKS || list(r.ok.repos).some((x) => list(asObj(x).hooks).length > MAX_HOOKS)) {
      found.push({ categories: [...HOOK_CATEGORIES].map((c) => `${UNKNOWN_PREFIX}${c}`), by: 'pre-commit', subject: 'The pre-commit config', dir: '.', reason: null,
        partialWhy: "The pre-commit config has more hooks than pipegen reads, so it can't tell what the rest run." });
      unrecognised.push('(more hooks than pipegen reads)');
    }
    const tag = (fs: Found[], reason: Reason): Found[] => fs.map((f) => {
      const { langs: _langs, ...rest } = f;
      void _langs;
      return { ...(reason === 'hook-repo' ? rest : f), reason: f.reason ?? reason };
    });
    const long = (fs: Found[], complete: boolean): Found[] => (complete ? fs : fs.map((f) => ({ ...f, reason: f.reason ?? 'long' })));
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
        // P57 (C4): pre-commit and prek also skip a hook by its alias
        const alias = typeof hook.alias === 'string' && regexSafe(hook.alias) && hook.alias !== '' ? hook.alias : undefined;
        const entry = typeof hook.entry === 'string' && regexSafe(hook.entry) ? hook.entry : undefined;
        let hookFound: Found[] = [];
        // the words the hook runs with, for the formatter rule (PS14): the entry and args, or the args of a known hook
        let words: string[] = [];
        if (local) {
          // `language: fail` prints its entry as a message and `pygrep` reads it as a regex; `script` and
          // `unsupported_script` run the entry as a file in the repo, and `docker_image` starts with an image name
          // (https://pre-commit.com/#supported-languages): none of them runs the named tool (fix round 2, N2)
          if (entry !== undefined && !(typeof hook.language === 'string' && NOT_A_COMMAND_LANGUAGES.has(hook.language))) {
            const hw = hookWords(entry, allArgs);
            words = hw.text.split(' ');
            hookFound = long(scan(hw.text), hw.complete);
          }
        } else if (entry !== undefined) {
          const hw = hookWords(entry, allArgs);
          words = hw.text.split(' ');
          hookFound = long(known ? scan(hw.text) : tag(scan(hw.text), 'hook-repo'), hw.complete);
        } else if (id !== '') {
          const tools = known ? ctx.sigs.hooks.get(hookRepoKey(url, id)) : undefined;
          const hw = hookWords(id, allArgs);
          words = tools !== undefined ? args : hw.text.split(' ');
          hookFound = tools !== undefined
            ? tools.filter((t) => flagsAllow(t, args, complete)).map((t) => foundOf(t, '.', commandReason(t, args) ?? (complete ? null : 'long')))
            : long(tag(scan(hw.text), 'hook-repo'), hw.complete);
        }
        hookFound = hookFound.map((f) => ({ ...(FORMATTER_HOOKS.has(f.by) ? { ...f, formats: formatterFails(f.by, words) } : f), ...(id === '' ? {} : { hookId: id }), ...(alias === undefined ? {} : { hookAlias: alias }) }));
        // a file filter pipegen doesn't evaluate (they are Python regexes from the repo), or another stage
        const filtered = topFiltered || ['files', 'exclude', 'types', 'types_or', 'exclude_types'].some((k) => isSet(hook, k));
        if (filtered) hookFound = tag(hookFound, 'files');
        const stages = 'stages' in hook ? strs(hook.stages) : defaultStages;
        if (stages.length > 0 && !stages.some((st) => st === 'pre-commit' || st === 'commit')) hookFound = hookFound.map((f) => ({ ...f, reason: 'stage' }));
        // each hook's scripts are followed here, not at the end, so a hook whose script runs no known tool is seen (B4)
        const resolved = (await resolveScripts(ctx, hookFound)).filter((f) => f.composeSentinel !== true); // P59 (4): no job env here
        const lookalike = !local && !known; // a repo pipegen doesn't list: it can't see what the hook runs
        if (lookalike || !resolved.some((f) => f.categories.some((c) => !c.startsWith(UNKNOWN_PREFIX)))) {
          if (unrecognised.length < MAX_UNRECOGNISED) unrecognised.push(id !== '' && PLAIN_HOOK_ID.test(id) ? id : '(a hook without a readable id)');
        }
        found.push(...resolved);
      }
    }
    return { found, unrecognised };
  }
}

export async function readHooks(ctx: Ctx): Promise<Hooks> {
  const manager = ctx.p.precommit;
  const none: Hooks = { manager, where: '', readable: true, found: [], unrecognised: [] };
  if (manager === null) return none;
  const scan = async (text: string, base: string | null, mode: ShellMode) => {
    const g = gateOf([text], [], undefined, ctx.sigs.softEnv, ctx.sigs.configFiles);
    return gated(await resolveScripts(ctx, scanShell(text, base, ctx.sigs, ctx.budget, mode)), g).filter((f) => f.composeSentinel !== true || g.compose);
  };
  if (manager === 'husky') {
    const where = '.husky/pre-commit';
    const r = await ctx.read.text(where);
    if ('fail' in r) return { ...none, where: '.husky', readable: r.fail === 'missing' };
    return { manager, where, readable: true, found: await scan(r.ok, '.', HUSKY_SHELL), unrecognised: [] };
  }
  if (manager === 'pre-commit') {
    const config = await readPrecommitConfig(ctx);
    return { manager, where: HOOK_FILE['pre-commit'], readable: config.readable, found: config.found, unrecognised: config.unrecognised };
  }
  // lefthook: the first of lefthook.yml / lefthook.yaml that exists (readPrecommit's order)
  for (const where of ['lefthook.yml', 'lefthook.yaml']) {
    const r = await ctx.read.yaml(where);
    if ('fail' in r && r.fail === 'missing') continue;
    if ('fail' in r) return { ...none, where, readable: false };
    const hook = asObj(r.ok['pre-commit']);
    const all = [...Object.values(asObj(hook.commands)), ...list(hook.jobs)];
    const entries = all.slice(0, MAX_HOOKS).map(asObj);
    const found: Found[] = [];
    for (const e of entries) if (typeof e.run === 'string') found.push(...(await scan(e.run, firstSet(workingDir(e.root)), LEFTHOOK_SHELL)));
    // P57 (fail closed): commands past MAX_HOOKS aren't read: the rows they could cover are unknown, never missing
    return { manager, where, readable: all.length <= MAX_HOOKS, found, unrecognised: [] };
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
/** P57 (fail closed): every category a hook can count for, at the pre-commit layer or carried into CI. */
const HOOK_CATEGORIES: readonly string[] = ['format-lint', 'secrets', 'lint', 'type-check', 'dockerfile-lint', 'workflow-lint', 'format'];
/**
 * A formatter hook carries format when it writes files or checks them (formatterFails), or when a reason already keeps
 * it partial (a hook repo pipegen doesn't know, a file filter): it never makes the row covered then.
 */
const carried = (f: Found): string[] => {
  const out = f.categories.filter((c) => CARRIED.has(c.startsWith(UNKNOWN_PREFIX) ? c.slice(UNKNOWN_PREFIX.length) : c));
  if (FORMATTER_HOOKS.has(f.by) && (f.formats === true || f.reason !== null) && !out.includes('format')) out.push('format');
  return out;
};
/** P57 (C4): the carried tools of one config: one per (tool, reason, hook id), each with the categories it carries. */
function carriedTools(found: readonly Found[]): { f: Found; categories: string[] }[] {
  const tools = new Map<string, { f: Found; categories: string[] }>();
  for (const f of found) {
    const key = `${f.by}\u0000${f.reason ?? ''}\u0000${f.hookId ?? ''}\u0000${f.hookAlias ?? ''}`;
    const categories = carried(f);
    // a hook set up for another stage doesn't run in `pre-commit run` (its default stage is pre-commit)
    if (categories.length > 0 && f.reason !== 'stage' && !tools.has(key)) tools.set(key, { f, categories });
  }
  return [...tools.values()];
}
const skipKey = (h: Hit) => (h.hookSkip === undefined ? '' : `${h.hookSkip.unknown ? '?' : ''}${[...h.hookSkip.ids].sort().join(',')}`);

export async function hookRunHits(ctx: Ctx): Promise<void> {
  const reps = new Map<string, Hit>();
  for (const h of ctx.hits) {
    const key = `${h.by ?? ''}\u0000${h.fit.push ? 1 : 0}${h.fit.merge ? 1 : 0}${h.fit.deploy ? 1 : 0}\u0000${h.reason ?? ''}\u0000${h.hookRun === 'changed' || h.hookRun === 'part' ? h.hookRun : ''}\u0000${skipKey(h)}`;
    if ((h.hookRun === true || h.hookRun === 'changed' || h.hookRun === 'part') && !reps.has(key)) reps.set(key, h);
  }
  if (reps.size === 0) return;
  const yamlTools = carriedTools((await readPrecommitConfig(ctx)).found);
  for (const rep of reps.values()) {
    // P57 (C4): a prek run reads prek.toml first when there is one
    const prek = rep.by === PREK_ID ? await readPrekConfig(ctx) : 'absent';
    const file = prek === 'absent' ? HOOK_FILE['pre-commit'] : 'prek.toml';
    const where = cut(`${rep.where} → ${file}`);
    if (prek === 'unreadable') {
      if (ctx.hits.length >= MAX_HITS) return void (ctx.budget.truncated = true);
      ctx.hits.push({
        opaque: false, categories: [...CARRIED].map((c) => `${UNKNOWN_PREFIX}${c}`), by: rep.by as string, subject: 'The prek run', dir: '.', reason: null,
        partialWhy: "The prek run reads prek.toml before .pre-commit-config.yaml, and pipegen couldn't read prek.toml (a symbolic link, too large or not valid TOML), so it can't tell which hooks run.",
        fit: rep.fit, where,
      });
      continue;
    }
    const tools = prek === 'absent' ? yamlTools : carriedTools(prek);
    // the run's own SKIP reason says some hooks may not run; each hook's own row is lowered only when SKIP names it
    const repReason = rep.reason === 'skip' ? null : rep.reason;
    for (const { f: t, categories } of tools) {
      if (ctx.hits.length >= MAX_HITS) {
        ctx.budget.truncated = true;
        return;
      }
      const subject = `${t.subject} in the pre-commit hooks`;
      if (rep.hookSkip?.unknown === true) {
        ctx.hits.push({
          opaque: false, categories: categories.map((c) => `${UNKNOWN_PREFIX}${c}`), by: t.by, subject, dir: '.', reason: null,
          partialWhy: `${subject} runs unless SKIP or PREK_SKIP names its hook, and that variable is set to a value pipegen can't read here, so it can't tell whether it runs.`,
          fit: rep.fit, where, ...(t.langs === undefined ? {} : { langs: t.langs }),
        });
        continue;
      }
      const skipped = [t.hookId, t.hookAlias].some((n) => n !== undefined && rep.hookSkip?.ids.has(n) === true);
      // fix round 1 (P8): a softEnv name set in the CI job reaches the hook's tool; its config files are looked for later
      const set = softEnvSet(t.softEnv, rep.jobEnv);
      // a run over changed files only is partial ('changed'), unless something already keeps the hook from running
      const reason = repReason ?? t.reason ?? (skipped ? 'skip' : null) ?? (rep.hookRun === 'changed' || rep.hookRun === 'part' ? rep.hookRun : null);
      const configured = set !== null && (reason === null || !MAY_NOT_RUN.has(reason));
      ctx.hits.push({
        opaque: false, categories, by: t.by, subject, dir: '.', reason: configured ? 'config' : reason,
        ...(configured ? { partialWhy: configWhy(subject, set) } : t.partialWhy !== undefined && categories.every((c) => c.startsWith(UNKNOWN_PREFIX)) ? { partialWhy: t.partialWhy } : {}), fit: rep.fit, where,
        ...(t.configFiles === undefined ? {} : { configFiles: t.configFiles }), ...(t.langs === undefined ? {} : { langs: t.langs }),
        ...(t.unplaced === undefined ? {} : { unplaced: t.unplaced }),
      });
    }
  }
}
