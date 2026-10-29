// Coverage mapper (see ../coverage.ts for the rules): tools found in shell text (scanShell) and container images (scanImage).
import { regexSafe } from '../../read/limits.js';
import { MAX_FLAG_WORDS, MAX_SCAN_BYTES, MAX_SCRIPT_PATTERNS, MAX_SCRIPT_TARGETS } from './bounds.js';
import { resolveDir } from './helpers.js';
import { safeText } from '../../util/safe-text.js';
import { UNKNOWN_PREFIX, commandReason, configTurnedOff, flagsAllow, foundOf, inputWords, inputWordsCapped, inputsCrowded, type Inputs } from './settings.js';
import { PRE_COMMIT_ID } from './signatures.js';
import { tokenize } from './tokenize.js';
import type { Budget, CommandRule, Compiled, Found, Reason } from './types.js';

// ---------- reading shell text (review M2: command position only; round 2: quotes, lists, groups, pipes) ----------

/** How a step's shell treats failures. GitHub: default `bash -e {0}`; `bash` adds -o pipefail; `sh` is `sh -e {0}`. */
/**
 * `script` (P51): the text is a repo script file pipegen follows (its condition why names the script). The condition
 * rules themselves (P51-P53) apply to every shell text: steps, package scripts, hooks and script files.
 */
export interface ShellMode { errexit: boolean; pipefail: boolean; script?: boolean }
export const DEFAULT_SHELL: ShellMode = { errexit: true, pipefail: false };

/** Shells GitHub runs with errexit off that pipegen reads as before (pwsh, powershell, python, cmd): `run:` text isn't sh there. */
const OTHER_STEP_SHELLS: ReadonlySet<string> = new Set(['pwsh', 'powershell', 'python', 'cmd']);

/**
 * The mode of a step's `shell:` (or defaults.run.shell). Known: none (the default), `bash`, `sh` (also by absolute path,
 * /bin or /usr/bin), and `bash|sh` followed only by allowlisted words (-e -u -x -v and combined or + forms, -l, --login,
 * `-o pipefail|errexit|nounset|xtrace`, --noprofile, --norc) then `{0}`; and pwsh, powershell, python and cmd as before
 * (errexit off). `noexec` (P52 d): bash or sh told not to run the commands (-n in a flag word, `-o noexec`), so nothing
 * in the step runs. null: a spec pipegen doesn't know (`perl {0}`, `bash -c {0}`, `bash --posix {0}`); it can't tell
 * what runs, so the step is opaque (unknown, never missing: re-review 2, `bash -el {0}` of conda setups).
 */
export function shellMode(v: unknown): ShellMode | 'noexec' | null {
  if (v === undefined || v === null) return DEFAULT_SHELL;
  if (typeof v !== 'string' || !regexSafe(v)) return null;
  const s = v.trim();
  if (s === 'bash') return { errexit: true, pipefail: true };
  if (s === 'sh') return { errexit: true, pipefail: false };
  const parts = s.split(/\s+/).slice(0, 17);
  const prog = parts[0] ?? '';
  if (OTHER_STEP_SHELLS.has(basename(prog))) return { errexit: false, pipefail: false };
  const sh = /^(?:(?:\/usr)?\/bin\/)?(bash|sh)$/.exec(prog)?.[1];
  if (sh === undefined || parts.length > 16 || parts[parts.length - 1] !== '{0}') return null;
  const mid = parts.slice(1, -1);
  // told not to run the commands: nothing in the step runs (checked first, so `-l -n` is noexec, not unknown)
  if (mid.some((x, i) => /^-[A-Za-z]*n[A-Za-z]*$/.test(x) || (/^-[A-Za-z]*o$/.test(x) && mid[i + 1] === 'noexec'))) return 'noexec';
  let errexit = false;
  let pipefail = false;
  for (let i = 0; i < mid.length; i++) {
    const x = mid[i] as string;
    if (x === '--noprofile' || x === '--norc' || x === '--login' || x === '-l') continue;
    const o = /^-([euxvl]*)o$/.exec(x);
    if (o !== null) {
      const opt = mid[i + 1] ?? '';
      if (!SHELL_OPTIONS.has(opt)) return null;
      if ((o[1] as string).includes('e') || opt === 'errexit') errexit = true;
      if (opt === 'pipefail') pipefail = true;
      i++;
      continue;
    }
    if (!SHELL_FLAGS.test(x) && !/^-[euxvl]+$/.test(x)) return null;
    if (x.startsWith('-') && x.includes('e')) errexit = true;
  }
  return { errexit, pipefail: sh === 'bash' && pipefail };
}

/**
 * P52 (e): a script run directly runs under its shebang: only bash or sh (by path or `/usr/bin/env bash|sh`), with
 * allowlisted flags (-e -u -x -v, combined or + forms), is read; anything else (`-n`, /bin/true, python, `env -S`, no
 * shebang) gives no coverage.
 */
export function shebangOk(text: string): boolean {
  const first = (text.split('\n', 1)[0] ?? '').replace(/\r$/, '');
  const m = /^#!\s*(?:\/usr\/bin\/env\s+(?:bash|sh)|(?:\/usr)?\/bin\/(?:bash|sh))((?:\s+\S+){0,4})\s*$/.exec(first);
  if (m === null) return false;
  return (m[1] ?? '').trim().split(/\s+/).filter((x) => x !== '').every((x) => SHELL_FLAGS.test(x));
}

const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** Words after which the next non-flag word is a command. */
/** P51: the compound commands whose body runs only under a condition. */
const CONDITIONAL_KW: ReadonlySet<string> = new Set(['if', 'case', 'while', 'until', 'select']);
/** P52 (a): the commands after which the rest of an `&&` chain still runs unconditionally (with argument checks, see chainSafe). */
const CHAIN_SAFE: ReadonlySet<string> = new Set(['cd', 'pushd', 'export', 'set', 'source', '.']);
/** P50 (C1): the shells whose flags are allowlisted before a script (anything else: the command gives no coverage). */
const SHELLS: ReadonlySet<string> = new Set(['sh', 'bash', 'zsh', 'dash']);
/** -e -u -x -v and their combined and `+` forms (-eux, +x). */
const SHELL_FLAGS = /^[-+][euxv]+$/;
/** The `-o` options that keep a script running as written. */
const SHELL_OPTIONS: ReadonlySet<string> = new Set(['pipefail', 'errexit', 'nounset', 'xtrace']);
/** A word that names a shell script by its ending, whatever its path (`$DIR/x.sh`, `/opt/x.sh`, `"x.sh"`). */
const looksLikeScript = (w: string) => /\.sh['"]?$/.test(w);
const WRAPPERS = new Set(['sudo', 'time', 'npx', 'bunx', 'uvx', 'env', 'nohup', 'exec', 'command', 'xargs', 'sh', 'bash', 'zsh', 'dash', 'nyc', 'cross-env']);
/** Commands that always succeed and do nothing a check needs (fix round 2, N1). */
export const OK_COMMANDS: ReadonlySet<string> = new Set(['true', ':', 'echo', 'printf']);
/** Flags of a wrapper that take the next word as their value. */
const WRAPPER_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-T', '-U', '--user', '--group', '--chdir', '--host', '--prompt']),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  xargs: new Set(['-I', '-L', '-n', '-P', '-s', '-d', '-E', '-a']),
};
/** Two-word wrappers: pnpm dlx, uv run, python -m, … */
const SUB_WRAPPERS: Readonly<Record<string, readonly string[]>> = {
  pnpm: ['dlx', 'exec'], yarn: ['dlx', 'exec'], npm: ['exec'], bun: ['x'], uv: ['run'], pipx: ['run'], poetry: ['run'],
  pdm: ['run'], hatch: ['run'], pipenv: ['run'], python: ['-m'], python3: ['-m'],
};
/**
 * Task 5: wrappers whose flags pipegen knows in full. A flag outside these lists ends the match (no command at all), so
 * the value of a flag pipegen doesn't know (`uv run --with ruff python …`) can never be read as the command.
 * - uv run: https://docs.astral.sh/uv/reference/cli/#uv-run (checked 2026-10-27; `-m`/`--module` is a plain flag).
 * - nyc: its options are the nyc entries of https://github.com/istanbuljs/schema/blob/master/index.js (array, string and
 *   number options take a value); nyc exits with the wrapped command's exit code
 *   (https://github.com/istanbuljs/nyc/blob/main/bin/nyc.js: `let exitCode = process.exitCode || code`).
 */
interface StrictFlags { valued: ReadonlySet<string>; boolean: ReadonlySet<string> }
const STRICT_WRAPPER_FLAGS: Readonly<Record<string, StrictFlags>> = {
  uv: {
    valued: new Set(['--allow-insecure-host', '--trusted-host', '--cache-dir', '--color', '--config-file', '--config-setting', '--config-settings', '-C',
      '--config-settings-package', '--default-index', '--directory', '--env-file', '--exclude-newer', '--exclude-newer-package', '--extra',
      '--extra-index-url', '--find-links', '-f', '--fork-strategy', '--group', '--index', '--index-strategy', '--index-url', '-i', '--keyring-provider',
      '--link-mode', '--no-binary-package', '--no-build-isolation-package', '--no-build-package', '--no-editable-package', '--no-extra', '--no-group',
      '--no-sources-package', '--only-group', '--package', '--prerelease', '--prerelease-package', '--project', '--python', '-p', '--python-platform',
      '--refresh-package', '--reinstall-package', '--resolution', '--upgrade-group', '--upgrade-package', '-P', '--with', '-w', '--with-editable',
      '--with-requirements']),
    boolean: new Set(['--active', '--all-extras', '--all-groups', '--all-packages', '--compile-bytecode', '--compile', '--exact', '--frozen', '--gui-script',
      '--isolated', '--locked', '--managed-python', '--module', '-m', '--no-binary', '--no-build', '--no-build-isolation', '--no-cache', '--no-cache-dir',
      '-n', '--no-config', '--no-default-groups', '--no-dev', '--no-editable', '--no-env-file', '--no-index', '--no-managed-python', '--no-progress',
      '--no-project', '--no_workspace', '--no-python-downloads', '--no-require-build-hashes', '--no-sources', '--no-sync', '--offline', '--only-dev',
      '--quiet', '-q', '--refresh', '--reinstall', '--force-reinstall', '--require-build-hashes', '--script', '-s', '--system-certs', '--upgrade', '-U',
      '--verbose', '-v']),
  },
  nyc: {
    valued: new Set(['--cwd', '--nycrc-path', '--temp-dir', '-t', '--temp-directory', '--exclude', '-x', '--include', '-n', '--extension', '-e',
      '--ignore-class-methods', '--parser-plugins', '--require', '-i', '--branches', '--functions', '--lines', '--statements', '--reporter', '-r',
      '--report-dir', '--cache-dir']),
    boolean: new Set(['--exclude-node-modules', '--auto-wrap', '--es-modules', '--compact', '--preserve-comments', '--produce-source-map', '--source-map',
      '--instrument', '--exclude-after-remap', '--per-file', '--check-coverage', '--show-process-tree', '--skip-empty', '--skip-full', '--silent', '-s',
      '--all', '-a', '--eager', '--cache', '-c', '--babel-cache', '--use-spawn-wrap', '--hook-require', '--hook-run-in-context',
      '--hook-run-in-this-context', '--clean', '--in-place', '--exit-on-error', '--delete', '--complete-copy']),
  },
};
/** `yarn eslint .` and `pnpm eslint .` run a package binary: the next word is a command too. */
const BIN_RUNNERS = new Set(['yarn', 'pnpm']);
const DOCKER_VALUE_FLAGS = new Set(['-v', '--volume', '-e', '--env', '--env-file', '-w', '--workdir', '-u', '--user', '-p', '--publish', '--name',
  '--entrypoint', '--network', '--platform', '--mount', '-l', '--label', '--label-file', '--add-host', '--pull', '-m', '--memory', '--cpus',
  '--cidfile', '-h', '--hostname', '--security-opt', '--cap-add', '--cap-drop', '--device', '--dns', '--log-driver', '--log-opt',
  '--restart', '--runtime', '--tmpfs', '--ulimit', '--group-add', '--shm-size', '--ipc', '--pid', '--gpus', '--expose', '--link',
  '--volumes-from', '--stop-signal', '-a', '--attach', '-c', '--cpu-shares', '--ip', '--mac-address', '--userns', '--uts']);
/** Shell keywords: the next word is a command; in a condition its exit status is consumed. */
const COND_KEYWORDS = new Set(['if', 'elif', 'while', 'until']);
const BODY_KEYWORDS = new Set(['then', 'do', 'else']);
const END_KEYWORDS = new Set(['fi', 'done', 'esac']);
/**
 * A call that only prints the version or help, not a run. Fix round 1: also Go's one-dash `-version` and `-help`
 * (actionlint) and `-?` (TypeScript).
 */
const PROBE_WORDS: ReadonlySet<string> = new Set(['--version', '--help', '-version', '-help', '-?']);
export const probeCall = (args: readonly string[]) =>
  args.some((a) => PROBE_WORDS.has(a)) || (args.length === 1 && ['-v', '-V', '-h'].includes(args[0] as string));
/** Script names after `npm run` etc. (ruling S5): test, lint, or test:… / lint:…, counted by name. */
const OWN_NAME_RE = /^(?:test|lint)(?::[A-Za-z0-9_.-]{1,64})?$/;
/** Task 5: any other script name, counted only when the script's own text runs a known test or lint tool. */
const SCRIPT_NAME_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.:-]{0,63}$/;
/** Fix round 3: a script name or an npm-run-all glob, as it may appear in the `by` phrase. */
const SCRIPT_PATTERN_RE = /^[A-Za-z0-9_.*][A-Za-z0-9_.:*-]{0,63}$/;
const PACKAGE_MANAGERS = ['npm', 'pnpm', 'yarn', 'bun'];
/** Task 5: a script that only fixes (lint:fix, lint-fix, format:write) is not a check. */
const fixOnly = (name: string) => name.toLowerCase().split(/[:_-]/).some((seg) => seg === 'fix' || seg === 'write');
const ownName = (name: string) => OWN_NAME_RE.test(name) && !fixOnly(name);
const TEST_CATEGORIES = ['unit-tests', 'full-tests'] as const;
/** pytest modes that collect or list tests without running them (https://docs.pytest.org/en/stable/reference/reference.html#command-line-flags). */
export const PYTEST_NO_RUN: ReadonlySet<string> = new Set(['--co', '--collect-only', '--setup-plan', '--fixtures', '--fixtures-per-test', '--markers']);
/**
 * What an own script can count for, from what its text runs (Task 5). Plan P Task 3 (PS11): also format, type-check,
 * coverage, dead-code and duplication (`npm run typecheck`, `format:check`, `test:coverage`, `knip`).
 */
export const SCRIPT_CATEGORIES: ReadonlySet<string> = new Set(['unit-tests', 'full-tests', 'lint', 'format-lint', 'format', 'type-check', 'coverage', 'dead-code',
  'duplication']);

/**
 * Task 5: tox and nox count as the project's own test runner (like `npm test`) only when the command line picks no
 * other envs or sessions. A long flag also matches by an abbreviation (argparse's default); short flags may be grouped.
 * tox 4 (https://tox.wiki/en/latest/reference/config.html: "Set a CLI option's default with TOX_<option>", so TOX_ENV
 * picks envs like -e); TOXENV and every other variable named TOX… or NOX… is handled where the step's environment is read.
 */
const TOX_RUN_SUBS: ReadonlySet<string> = new Set(['run', 'r', 'run-parallel', 'p']);
const TOX_LONG = ['--env', '--labels', '--factors', '--notest', '--skip-env', '--override', '--listenvs', '--listenvs-all', '--showconfig', '--help-ini', '--devenv'];
const TOX_SHORT = 'emfnxla';
const NOX_LONG = ['--session', '--sessions', '--keywords', '--tags', '--list', '--list-sessions', '--json', '--install-only', '--usage'];
const NOX_SHORT = 'sektl';
function picksOther(flag: string, long: readonly string[], short: string): boolean {
  if (flag.startsWith('--')) {
    const name = flag.split('=')[0] as string;
    return name.length > 2 && long.some((f) => f.startsWith(name));
  }
  return [...(flag.slice(1).split('=')[0] as string)].some((c) => short.includes(c));
}

/**
 * Task 5: `pre-commit run` words (after `run`) that run every pre-commit-stage hook on every file: `--all-files`/`-a`,
 * no hook id, no other stage, no other config, no file list (https://pre-commit.com/#pre-commit-run). Without
 * --all-files, `pre-commit run` checks the staged files, and a CI checkout has none.
 */
export function preCommitAllFiles(words: readonly string[]): boolean {
  let all = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    const r = redirection(w);
    if (r !== null) {
      if (!r) i++;
      continue;
    }
    if (!w.startsWith('-')) return false; // a hook id, or the value of a flag pipegen doesn't know
    const eq = w.indexOf('=');
    const name = eq < 0 ? w : w.slice(0, eq);
    const value = eq < 0 ? undefined : w.slice(eq + 1);
    if ((name === '-a' || name === '--all-files') && value === undefined) all = true;
    else if (value === undefined && ['--show-diff-on-failure', '-v', '--verbose', '--fail-fast'].includes(name)) continue;
    else if (name === '--color') i += value === undefined ? 1 : 0;
    else if (name === '--hook-stage') {
      const stage = value ?? words[++i];
      if (stage !== 'pre-commit' && stage !== 'commit') return false;
    } else return false;
  }
  return all;
}

const basename = (w: string) => w.slice(w.lastIndexOf('/') + 1);
const NPM_PROVENANCE_ID = 'npm-provenance';
/** The image's name: no registry or owner, no :tag or @digest (ghcr.io/zricethezav/gitleaks:v8 → gitleaks). */
export function imageName(image: string): string {
  const at = image.indexOf('@');
  const noDigest = at < 0 ? image : image.slice(0, at);
  const name = basename(noDigest);
  const colon = name.indexOf(':');
  return colon < 0 ? name : name.slice(0, colon);
}
/**
 * A shell script file of the repo run as a command (`scripts/test.sh`, `./ci.sh`, after `bash`/`sh` or not): its path
 * without leading `./`, or null. Only plain relative paths of ASCII letters, digits and . _ - / ending in `.sh` (no `..`
 * part, at most 200 characters), so the path is safe to show and can't leave the repo by its text.
 */
export function repoScriptFile(w: string): string | null {
  const path = stripDotSlash(w);
  if (path.length > 200 || !/^[A-Za-z0-9_.][A-Za-z0-9_./-]*\.sh$/.test(path) || path.split('/').some((x) => x === '..' || x === '.' || x === '')) return null;
  return path;
}
const stripDotSlash = (w: string) => {
  let i = 0;
  while (w.startsWith('./', i)) i += 2;
  return w.slice(i);
};

/**
 * A redirection word (`>`, `2>&1`, `&>out`, `<in`): null when the word isn't one; true when it carries its target
 * (`>out`, `2>&1`); false when the target is the next word (`>`, `2>`, `<`).
 */
function redirection(w: string): boolean | null {
  let j = 0;
  while (j < w.length && w[j]! >= '0' && w[j]! <= '9') j++;
  if (!(w[j] === '<' || w[j] === '>' || w.startsWith('&>', j))) return null;
  while (j < w.length && (w[j] === '<' || w[j] === '>' || w[j] === '&' || w[j] === '|')) j++;
  return j < w.length;
}

/**
 * Tools found in shell text (a run step, a hook script, a hook entry). See the module header for what counts as a
 * command and when its failure can't fail the step. `cd <dir>` moves the directory for the rest of the text.
 */
/**
 * Fix round 2 (N1): one command scanShell saw, for a caller that classes every command of a script (`onCmd`).
 * `wrapper`: the word only starts another command (npx, env, cross-env, uv run, yarn <bin>…), which is reported too.
 * `dead`: it never runs (after a top-level `exit`, or right of `true ||` / `false &&`).
 */
export interface CmdInfo { name: string; args: readonly string[]; dir: string | null; reason: Reason | null; dead: boolean; wrapper: boolean; afterBin: boolean }

export function scanShell(text: string, base: string | null, sigs: Compiled, budget: Budget, mode: ShellMode = DEFAULT_SHELL, onCmd?: (c: CmdInfo) => void): Found[] {
  budget.bytes += text.length;
  if (budget.bytes > MAX_SCAN_BYTES) {
    budget.truncated = true;
    return [];
  }
  const toks = tokenize(text);
  const n = toks.length;
  const isWord = (k: number) => k >= 0 && k < n && toks[k]!.op === null;
  const word = (k: number) => (isWord(k) ? toks[k]!.w : null);

  // Matching group brackets (forward pass with a stack), so the right-to-left pass knows what a ')' closes. A compound
  // command (if … fi, for/while/until/select … done, case … esac) is a group too: fi/done/esac close only a compound
  // command, and one still open when a ')' or '}' comes stays unmatched (a plain word).
  const opener = new Int32Array(n).fill(-1);
  const closer = new Int32Array(n).fill(-1);
  const open: number[] = [];
  const depth = new Int32Array(n); // how many brackets and compound commands are open at k (fix round 1: `exit`)
  const pair = (k: number) => {
    const o = open.pop() as number;
    opener[k] = o;
    closer[o] = k;
  };
  for (let k = 0; k < n; k++) {
    const t = toks[k]!;
    depth[k] = open.length;
    if (t.op === '(' || t.op === '{' || t.op === '$(' || t.kw === 'open') open.push(k);
    else if (t.kw === 'close') {
      if (open.length > 0 && toks[open[open.length - 1]!]!.kw === 'open') pair(k);
    } else if (t.op === ')' || t.op === '}') {
      while (open.length > 0 && toks[open[open.length - 1]!]!.kw === 'open') open.pop();
      if (open.length > 0) pair(k);
    }
  }
  /**
   * P52 (b): whether the `for` at k loops over a literal list (`for t in unit api`): no `in` (the positional
   * parameters), a word with `$` or a backtick, a `$( … )`, or an empty list is not literal (it may run zero times).
   */
  const literalForList = (k: number): boolean => {
    if (word(k + 2) !== 'in') return false;
    let items = 0;
    for (let j = k + 3; j < n; j++) {
      const t = toks[j]!;
      if (t.op === ';' || t.op === '\n' || (t.op === null && t.w === 'do')) return items > 0;
      if (t.op !== null || /[$`]/.test(t.w)) return false;
      items++;
    }
    return false;
  };
  // P51: how many if / case / while / until compound commands hold each token (a prefix sum over their ranges)
  const condDepth = new Int32Array(n + 1);
  let firstLoop = -1; // P54: the first while/until/select or non-literal for
  { // P53: for every shell text (steps, package scripts, hooks and followed script files)
    for (let k = 0; k < n; k++) {
      if (toks[k]!.kw !== 'open' || !(CONDITIONAL_KW.has(toks[k]!.w) || (toks[k]!.w === 'for' && !literalForList(k)))) continue;
      if (toks[k]!.w !== 'if' && toks[k]!.w !== 'case' && firstLoop < 0) firstLoop = k; // P54: a loop that may run zero times
      condDepth[k + 1]! += 1;
      condDepth[closer[k]! >= 0 ? closer[k]! : n]! -= 1;
    }
    for (let k = 1; k <= n; k++) condDepth[k]! += condDepth[k - 1]!;
  }
  const closes = (k: number) => toks[k]!.op === ')' || toks[k]!.op === '}' || (toks[k]!.kw === 'close' && opener[k]! >= 0);
  const opens = (k: number) => toks[k]!.op === '(' || toks[k]!.op === '{' || toks[k]!.op === '$(' || (toks[k]!.kw === 'open' && closer[k]! >= 0);
  /** Whether the right side of the `||` at k lets the list succeed (anything but exit <non-zero>, return <non-zero>, false). */
  const rightSwallows = (k: number) => {
    let j = k + 1;
    const end = toks[j]?.op === '{' || toks[j]?.op === '(' ? Math.min(closer[j]! < 0 ? n : closer[j]!, j + MAX_FLAG_WORDS) : j + 1;
    for (; j <= end && j < n; j++) {
      const w = word(j);
      if (w === null || (j > k + 1 && isWord(j - 1))) continue; // only words in command position
      if (w === 'false') return false;
      if ((w === 'exit' || w === 'return') && word(j + 1) !== '0') return false;
    }
    return true;
  };

  // Right to left: where each simple command ends, and whether its failure is swallowed by a later `||`, hidden by a
  // later pipe stage, exempt from errexit by a later `&&`, or run in the background by a later `&`. A group (and a
  // compound command) takes on the state of what follows it.
  const segEnd = new Int32Array(n);
  const swallowed = new Uint8Array(n);
  const piped = new Uint8Array(n);
  const andAfter = new Uint8Array(n);
  const background = new Uint8Array(n);
  type State = { sw: number; pp: number; aa: number; bg: number };
  let cur: State = { sw: 0, pp: 0, aa: 0, bg: 0 };
  let outer: State = { sw: 0, pp: 0, aa: 0, bg: 0 }; // what a list end inside the current group goes back to
  const stack: { outer: State; cur: State }[] = [];
  let end = n;
  for (let k = n - 1; k >= 0; k--) {
    const op = toks[k]!.op;
    if (op !== null) end = k;
    segEnd[k] = end;
    if (closes(k)) {
      stack.push({ outer, cur });
      // `VAR=$( … )` keeps the substitution's status; in any other command `$( … )` can't fail the step.
      const o = opener[k]!;
      const subst = o >= 0 && toks[o]!.op === '$(' && !(isWord(o - 1) && (toks[o - 1]!.w.endsWith('=')) && !isWord(o - 2));
      outer = { ...cur, sw: subst ? 1 : cur.sw };
      cur = { ...outer };
    } else if (opens(k)) {
      const f = stack.pop();
      if (f) {
        outer = f.outer;
        cur = f.cur;
      }
    } else if (op === ';' || op === '\n') {
      cur = { ...outer };
    } else if (op === '&') { // the and-or list before it runs in the background
      cur = { ...outer, bg: 1 };
    } else if (op === '&&') {
      cur = { ...cur, pp: outer.pp, aa: 1 };
    } else if (op === '||') {
      cur = { ...cur, sw: rightSwallows(k) ? 1 : outer.sw, pp: outer.pp, aa: 0 };
    } else if (op === '|') {
      cur = { ...cur, pp: 1 };
    }
    swallowed[k] = cur.sw;
    piped[k] = cur.pp;
    andAfter[k] = cur.aa;
    background[k] = cur.bg;
  }
  // The step's last command list starts after the last list end that has a word after it.
  let lastWord = n - 1;
  while (lastWord >= 0 && !isWord(lastWord)) lastWord--;
  let lastList = -1;
  for (let k = lastWord; k >= 0; k--) {
    const op = toks[k]!.op;
    if (op === ';' || op === '&' || op === '\n') {
      lastList = k;
      break;
    }
  }

  const found: Found[] = [];
  const seen = new Set<string>(); // one finding per tool, directory and reason per text
  const add = (found0: Found) => {
    // P52 (c): after a `set` pipegen can't read, a run may be under `set -n` or anything: unknown, never covered
    const f: Found = opaqueSet && found0.categories.some((c) => !c.startsWith(UNKNOWN_PREFIX))
      ? { ...found0, categories: found0.categories.map((c) => (c.startsWith(UNKNOWN_PREFIX) ? c : `${UNKNOWN_PREFIX}${c}`)), reason: null,
        partialWhy: `${found0.subject} runs after a \`set\` whose options pipegen can't read, so it can't tell whether it runs.` }
      : found0;
    const key = `${f.by}\u0000${f.dir ?? ''}\u0000${f.reason ?? ''}\u0000${f.hookRun === true ? 1 : 0}`;
    if (!seen.has(key)) {
      seen.add(key);
      found.push(f);
    }
  };
  let cwd = base;
  let errexit = mode.errexit;
  let pipefail = mode.pipefail;
  let inCondition = false;
  let negateEnd = -1;
  let functionEnd = -1; // tokens before this index are inside a function body
  let deadAfter = n; // fix round 1 (M3): commands after an unconditional top-level `exit` never run
  let deadTo = -1;   // fix round 2 (N1): commands up to here are the right side of `true ||` or `false &&`
  let lastCmd: { kind: 'ok' | 'fail' | 'other'; start: number; end: number } | null = null; // the last command run, where it starts and its list end
  const isDead = (k: number) => k > deadAfter || k <= deadTo;
  let containerEnd = -1; // P50 (M1): words before this index are the command of a `docker run` container
  // P51/P52 (script files only): the rest of this and-or list may not run (after `||`, or `&&` after a command not on
  // the CHAIN_SAFE list); an exit/return that can run under a condition was seen; the last command was CHAIN_SAFE
  let condChain = false;
  let orInList = false; // P54: this and-or list has a `||` so far
  let afterCondExit = false;
  let lastSafe = false;
  const exitFns = new Set<string>(); // P52 (b): script functions whose body can exit or return with success
  const fnStack: { name: string; close: number }[] = [];
  let opaqueSet = false; // P52 (c): a `set` with an argument pipegen can't read: later runs are unknown
  let shellScriptAt = -1; // P52 (e): the index of the script word after `bash|sh [flags]` (else the script runs directly)
  let binNext = -1; // the word after `yarn` / `pnpm` that may be a binary (or a script: classifyScript decides)
  // `( … )` and `$( … )` run in a subshell: `set` and `cd` inside them end at the closing bracket.
  const subshells: { close: number; errexit: boolean; pipefail: boolean; cwd: string | null }[] = [];

  /** Why the failure of the command at k can't fail the step, or null. */
  const shellReason = (k: number): Reason | null => {
    if (k < functionEnd) return 'function';
    const inLast = k > lastList;
    const exempt = swallowed[k] === 1 || (piped[k] === 1 && !pipefail) || background[k] === 1 || inCondition || k < negateEnd
      || (!errexit && !inLast) || (errexit && andAfter[k] === 1 && !inLast);
    if (exempt) return 'suppressed';
    // P51: in a followed script, a run inside if/case/while/until, right of a test's && or ||, or after a conditional
    // exit/return runs only under a condition
    // P54: an && chain whose status is the run's final status (the last list, top level, no `||` in it, nothing
    // conditional before it) is unconditional: an earlier failure in it fails the run visibly. Anywhere else bash's
    // set -e ignores a failure inside an && list, so a skipped check would be hidden.
    const lastChain = condChain && !orInList && k > lastList && depth[k] === 0 && condDepth[k] === 0 && !afterCondExit && !(firstLoop >= 0 && firstLoop < k);
    // P53: the same rules for every shell text; a followed script file names itself in the why
    if (!(condDepth[k]! > 0 || (condChain && !lastChain) || afterCondExit)) return null;
    return mode.script === true ? 'script-condition' : 'shell-condition';
  };
  const argsAfter = (k: number) => {
    const out: string[] = [];
    for (let j = k + 1; j < Math.min(segEnd[k]!, k + 1 + MAX_FLAG_WORDS); j++) out.push(toks[j]!.w);
    return out;
  };
  /** The words right after k equal `rest`. */
  const followedBy = (k: number, rest: readonly string[]) => rest.every((x, i) => word(k + 1 + i) === x);
  /** Signatures and own scripts for the command word at k (`name` = its basename, or an image name). */
  const match = (k: number, w: string, name: string) => {
    if (isDead(k)) return;
    const args = argsAfter(k);
    if (probeCall(args)) return;
    // Plan P Task 3: a command line with more words than pipegen reads may hide a soft flag past them
    const complete = segEnd[k]! - k - 1 <= MAX_FLAG_WORDS;
    const tryRules = (rules: CommandRule[] | undefined) => {
      for (const r of rules ?? []) {
        if (!followedBy(k, r.rest) || r.excludes.some((x) => followedBy(k, x)) || !flagsAllow(r.tool, args, complete)) continue;
        const target = r.tool.scanTarget === undefined ? null : imageTarget(args.slice(r.rest.length));
        if (target !== null && target !== 'unknown' && target !== r.tool.scanTarget) continue;
        const f = foundOf(r.tool, cwd, shellReason(k) ?? (target === 'unknown' ? 'target' : null) ?? commandReason(r.tool, args) ?? (complete ? null : 'long'),
          configTurnedOff(r.tool, args));
        // `pre-commit run --all-files` at the repo root (the whole list of words read: none past MAX_FLAG_WORDS); in
        // another folder pre-commit reads that folder's .pre-commit-config.yaml (fix round 1, I2)
        if (r.tool.id === PRE_COMMIT_ID && r.rest.length === 1 && r.rest[0] === 'run' && segEnd[k]! - k - 1 <= MAX_FLAG_WORDS
          && cwd === '.' && preCommitAllFiles(args.slice(1))) f.hookRun = true;
        if (r.tool.id === NPM_PROVENANCE_ID) f.envGate = 'npm';
        add(f);
      }
    };
    if (w.includes('/')) tryRules(sigs.byPath.get(stripDotSlash(w)));
    tryRules(sigs.byFirstWord.get(name));
    // DoD run (fastapi): `bash scripts/tests-start.sh`, `./ci.sh`: a shell script file from the repo, followed by
    // resolveScripts (its own text read like a step's), so its tests and lint count under "your own `<file>`"
    const file = repoScriptFile(w);
    // P50 (I4, M1): a `.sh` command pipegen can't place (a variable or an absolute or `..` path), or one a container
    // runs (its own copy, not the repo's), is unknown for every service, never missing
    const unplaced = file === null && looksLikeScript(w) ? `${safeText(w, 60)} runs a script file pipegen can't place` : null;
    const contained = file !== null && k < containerEnd ? `${file} runs inside a container, from the image's own copy` : null;
    if (unplaced !== null || contained !== null) {
      add({ categories: UNKNOWN_SCRIPT_CATEGORIES, by: 'a script file', subject: 'A script file', dir: null, reason: null, partialWhy: `${unplaced ?? contained}, so pipegen can't tell what it runs.` });
      return;
    }
    if (file !== null) {
      add({ categories: [], by: `your own \`${file}\``, subject: `Your own \`${file}\``, dir: cwd, reason: shellReason(k), scriptFile: file, ...(k === shellScriptAt ? {} : { scriptDirect: true }) });
      return;
    }
    if (w !== name) return;
    // The service's own scripts (ruling S5): npm test, npm run test|lint, pnpm|yarn|bun [run] test|lint, pytest,
    // python -m pytest; never a script that only fixes. Task 5: `npm|pnpm|yarn|bun run <other name>` (counted once
    // resolveScripts has read the script's text) and the tox / nox runners. Only fixed words and a script name
    // matching OWN_NAME_RE or SCRIPT_NAME_RE go into the phrase.
    let words: string[] | null = null;
    let script: string | undefined;
    let byName: string | undefined;
    let envGate: Found['envGate'];
    const a = word(k + 1);
    const b = word(k + 2);
    if (name === 'pytest') words = args.some((x) => PYTEST_NO_RUN.has(x)) ? null : ['pytest'];
    else if ((name === 'python' || name === 'python3') && a === '-m' && b === 'pytest') words = args.some((x) => PYTEST_NO_RUN.has(x)) ? null : [name, '-m', 'pytest'];
    else if (name === 'coverage' && a === 'run') {
      // DoD run (fastapi): `coverage run [flags] -m pytest` runs pytest and exits with its code (coverage.py docs,
      // https://coverage.readthedocs.io/en/latest/cmd.html#execution-coverage-run). Only `--flag[=value]` / `-x` words
      // before `-m`: a flag whose value is the next word stops it (pipegen doesn't read coverage's flag list).
      const m = args.indexOf('-m');
      if (m >= 1 && args[m + 1] === 'pytest' && args.slice(1, m).every((x) => /^-[A-Za-z]$|^--[a-z][a-z-]*(?:=\S*)?$/.test(x))) {
        words = args.some((x) => PYTEST_NO_RUN.has(x)) ? null : ['coverage', 'run', '-m', 'pytest'];
      }
    } else if (name === 'npm' && a !== null && NPM_TEST.has(a) && scriptFlagsOk(k + 1)) [words, byName] = [['npm', a], 'test'];
    else if (PACKAGE_MANAGERS.includes(name) && a !== null && (a === 'run' || (name === 'npm' && NPM_RUN.has(a))) && b !== null && ownName(b)
      && scriptFlagsOk(k + 2)) [words, byName] = [[name, a, b], b];
    else if (['pnpm', 'yarn', 'bun'].includes(name) && a !== null && ownName(a) && scriptFlagsOk(k + 1)) [words, byName] = [[name, a], a];
    else if (PACKAGE_MANAGERS.includes(name) && a !== null && (a === 'run' || (name === 'npm' && NPM_RUN.has(a))) && b !== null && SCRIPT_NAME_RE.test(b)
      && !fixOnly(b) && !OWN_NAME_RE.test(b) && scriptFlagsOk(k + 2)) {
      words = [name, a, b];
      script = b;
    } else if ((name === 'yarn' || name === 'pnpm') && a !== null && a !== 'run' && SCRIPT_NAME_RE.test(a) && !fixOnly(a) && !OWN_NAME_RE.test(a)
      && scriptFlagsOk(k + 1)) {
      // fix round 3: `yarn <script>` runs that script when package.json has it (resolveScripts drops it otherwise)
      words = [name, a];
      script = a;
    } else if (RUN_ALL.has(name) || name === 'concurrently') {
      // fix round 3: npm-run-all / run-s / run-p and concurrently `npm:` arguments run own scripts (followed when every
      // part is understood; a soft runner flag makes each partial)
      const call = scriptCall(name, args);
      if (call === null) return;
      if (call.capped) { // fix round 4 (N8): more patterns than pipegen reads, or one it can't: never covered, never missing
        add({ categories: UNKNOWN_SCRIPT_CATEGORIES, by: `your own \`${name}\``, subject: `Your own \`${name}\``, dir: cwd, reason: null, partialWhy: globCappedWhy(`your own \`${name}\``) });
        return;
      }
      if (call.unknown) return;
      for (const p of call.patterns) {
        if (!SCRIPT_PATTERN_RE.test(p) || fixOnly(p)) continue;
        add({
          categories: [], by: `your own \`${name} ${p}\``, subject: `Your own \`${name} ${p}\``, dir: cwd,
          reason: shellReason(k) ?? (call.soft ? 'soft' : null), script: p,
        });
      }
      return;
    } else if (name === 'tox') {
      const sub = toxRun(k);
      if (sub !== null) [words, envGate] = [sub === '' ? ['tox'] : ['tox', sub], 'tox'];
    } else if (name === 'nox' && noxRun(k)) [words, envGate] = [['nox'], 'nox'];
    if (words === null) return;
    const cmd = words.join(' ');
    const categories = script !== undefined ? [] : (words[words.length - 1] as string).startsWith('lint') ? ['lint'] : TEST_CATEGORIES;
    add({
      categories, by: `your own \`${cmd}\``, subject: `Your own \`${cmd}\``, dir: cwd, reason: shellReason(k),
      ...(script === undefined ? {} : { script }), ...(envGate === undefined ? {} : { envGate }), ...(byName === undefined ? {} : { byName }),
    });
  };
  /**
   * The words of the simple command at k, past redirections (more than MAX_FLAG_WORDS: false). `onWord` sees each
   * other word with the one before it, and returns false to refuse the command line.
   */
  const commandWords = (k: number, onWord: (w: string, prev: string) => boolean): boolean => {
    if (segEnd[k]! - k - 1 > MAX_FLAG_WORDS) return false;
    let prev = '';
    for (let j = k + 1; j < segEnd[k]!; j++) {
      const w = toks[j]!.w;
      const r = redirection(w);
      if (r !== null) {
        if (!r) j++;
        continue;
      }
      if (w === '--') { // the rest goes to the tests themselves; a pytest collect-only mode runs none (fix round 1, M2)
        for (let r = j + 1; r < segEnd[k]!; r++) if (PYTEST_NO_RUN.has(toks[r]!.w)) return false;
        return true;
      }
      if (!onWord(w, prev)) return false;
      prev = w;
    }
    return true;
  };
  /**
   * After `<pm> run <script>`: no flag before `--` other than --silent, -s or --if-present. npm reads such flags as its
   * own settings (`--workspace=x` runs another package's script; pnpm has --filter and -r), so the script read from
   * this directory's package.json might not be the one that runs.
   */
  const scriptFlagsOk = (k: number): boolean => {
    for (let j = k + 1; j < Math.min(segEnd[k]!, k + 1 + MAX_FLAG_WORDS); j++) {
      const w = toks[j]!.w;
      if (w === '--') return true;
      if (w.startsWith('-') && redirection(w) === null && !['--silent', '-s', '--if-present'].includes(w)) return false;
    }
    return segEnd[k]! - k - 1 <= MAX_FLAG_WORDS;
  };
  /** `tox` / `tox run|r|run-parallel|p` picking no other envs: the subcommand ('' for none), or null. */
  const toxRun = (k: number): string | null => {
    let sub = '';
    const ok = commandWords(k, (w, prev) => {
      if (w.startsWith('-')) return !picksOther(w, TOX_LONG, TOX_SHORT);
      if ((prev === '-p' || prev === '--parallel') && /^(?:auto|all|\d{1,4})$/.test(w)) return true;
      if (sub === '' && TOX_RUN_SUBS.has(w)) {
        sub = w;
        return true;
      }
      return false; // a positional word: another subcommand (list, exec, …) or a flag value pipegen doesn't know
    });
    return ok ? sub : null;
  };
  /** `nox` picking no sessions, with no positional word. */
  const noxRun = (k: number): boolean => commandWords(k, (w) => w.startsWith('-') && !picksOther(w, NOX_LONG, NOX_SHORT));
  /** If the command word at k starts a function definition, the index of its body's opening bracket, else -1. */
  const functionBody = (k: number) => {
    let j = k;
    if (toks[k]!.w === 'function') {
      if (!isWord(k + 1)) return -1;
      j = k + 2;
      if (toks[j]?.op === '(' && toks[j + 1]?.op === ')') j += 2;
    } else if (toks[k + 1]?.op === '(' && toks[k + 2]?.op === ')') {
      j = k + 3;
    } else return -1;
    while (toks[j]?.op === '\n') j++;
    return toks[j]?.op === '{' || toks[j]?.op === '(' || toks[j]?.kw === 'open' ? j : -1; // any compound command
  };
  /** Past a strict wrapper's flags (STRICT_WRAPPER_FLAGS): the index of its command, or -1 for a flag it doesn't know. */
  const skipStrictFlags = (k: number, f: StrictFlags) => {
    let j = k;
    for (let w = word(j); w !== null && w.startsWith('-'); w = word(j)) {
      if (w === '--') return j + 1;
      const eq = w.indexOf('=');
      const name = eq < 0 ? w : w.slice(0, eq);
      if (f.valued.has(name)) j += eq < 0 ? 2 : 1;
      else if (eq < 0 && (f.boolean.has(name) || (name.startsWith('--no-') && f.boolean.has(`--${name.slice(5)}`)))) j += 1;
      else return -1;
    }
    return j;
  };
  /**
   * P52 (a): a command after which an `&&` chain still runs unconditionally: cd, pushd, `export NAME[=…]`, `set` with
   * literal allowlisted flags, `source`/`.` of a plain repo script path. Anything else may make the rest conditional.
   */
  const chainSafe = (k: number, w: string): boolean => {
    if (!CHAIN_SAFE.has(w)) return false;
    const args: string[] = [];
    for (let j = k + 1; j < segEnd[k]!; j++) args.push(toks[j]!.w);
    if (w === 'export') return args.every((a) => /^[A-Za-z_][A-Za-z0-9_]*(?:=.*)?$/.test(a));
    if (w === 'set') return args.every((a, i) => SHELL_FLAGS.test(a) || /^[-+][euxv]*o$/.test(a) || (i > 0 && /^[-+][euxv]*o$/.test(args[i - 1] as string) && SHELL_OPTIONS.has(a)));
    if (w === 'source' || w === '.') return args.length === 1 && repoScriptFile(args[0] as string) !== null;
    return true; // cd, pushd
  };
  /** P50 (C1): past a shell's flags when every one is allowlisted (SHELL_FLAGS, `-o` SHELL_OPTIONS, `--`): the script's index, else -1. */
  const shellFlagsEnd = (k: number): number => {
    let j = k;
    for (let w = word(j); w !== null && (w.startsWith('-') || w.startsWith('+')) && j < segEnd[k - 1]!; w = word(j)) {
      if (w === '--') return j + 1;
      const o = /^[-+]([euxv]*)o$/.exec(w); // `-o name`, also after combined flags (`-eo pipefail`)
      if (o !== null) {
        if (!SHELL_OPTIONS.has(word(j + 1) ?? '')) return -1;
        j += 2;
        continue;
      }
      if (!SHELL_FLAGS.test(w)) return -1;
      j++;
    }
    return j;
  };
  const skipFlags = (k: number, wrapper: string) => {
    const strict = STRICT_WRAPPER_FLAGS[wrapper];
    if (strict !== undefined) return skipStrictFlags(k, strict);
    const valued = WRAPPER_VALUE_FLAGS[wrapper];
    let j = k;
    // cross-env takes only VAR=value words before the command (https://github.com/kentcdodds/cross-env, src/index.ts)
    if (wrapper === 'cross-env') {
      while (word(j) !== null && ASSIGN.test(word(j) as string)) j++;
      return j;
    }
    for (let w = word(j); w !== null && (w.startsWith('-') || (wrapper === 'env' && ASSIGN.test(w))); w = word(j)) j += valued?.has(w) ? 2 : 1;
    return j;
  };

  let cmd = true;
  let k = 0;
  while (k < n) {
    const op = toks[k]!.op;
    if (op !== null) {
      if (op === '||' || (op === '&&' && !lastSafe)) condChain = true;
      else if (op === ';' || op === '\n' || op === '&') condChain = false;
      if (op === '||') orInList = true;
      else if (op === ';' || op === '\n' || op === '&') orInList = false;
      if (op === ')' || op === '}') lastSafe = false; // a group's status: pipegen doesn't vouch for it
      if ((op === '(' || op === '$(') && closer[k]! >= 0) subshells.push({ close: closer[k]!, errexit, pipefail, cwd });
      while (subshells.length > 0 && subshells[subshells.length - 1]!.close <= k) {
        const s = subshells.pop()!;
        if (s.close === k) ({ errexit, pipefail, cwd } = s);
      }
      cmd = op !== ')' && op !== '}';
      // fix round 3: a `( … )` / `{ …; }` group holding only that command (and list ends) takes on its kind: `(true) || x`
      if ((op === ')' || op === '}') && lastCmd !== null && opener[k]! >= 0 && (toks[opener[k]!]!.op === '(' || toks[opener[k]!]!.op === '{')) {
        let j: number = lastCmd.end;
        while (j < k && (toks[j]!.op === ';' || toks[j]!.op === '\n')) j++;
        let i: number = opener[k]! + 1;
        while (i < lastCmd.start && toks[i]!.op === '\n') i++;
        if (j === k && i === lastCmd.start) lastCmd = { kind: lastCmd.kind, start: opener[k]!, end: k + 1 };
      }
      // `true || x`, `: || x`, `echo … || x`, `false && x`: x never runs (a bracketed x as a whole)
      if ((op === '||' || op === '&&') && lastCmd !== null && lastCmd.end === k && lastCmd.kind === (op === '||' ? 'ok' : 'fail') && k + 1 < n) {
        const after: number = k + 1;
        const group: boolean = (toks[after]!.op === '(' || toks[after]!.op === '{') && closer[after]! >= 0;
        const until: number = group ? closer[after]! : segEnd[after]!;
        deadTo = Math.max(deadTo, until);
        lastCmd = { kind: lastCmd.kind, start: lastCmd.start, end: group ? until + 1 : until };
      }
      k++;
      continue;
    }
    if (!cmd) {
      k++;
      continue;
    }
    const w = toks[k]!.w;
    if (ASSIGN.test(w)) { // VAR=value before a command
      k++;
      continue;
    }
    const redirect = redirection(w);
    if (redirect !== null) { // `> out cmd`, `2>&1 cmd`: a redirection before the command (and its target word)
      k += redirect ? 1 : 2;
      continue;
    }
    // A function definition, `name() { … }` or `function name [()] { … }`: its body runs only where it is called,
    // so tools inside it count as partial.
    const fnBody = functionBody(k);
    if (fnBody >= 0) {
      fnStack.push({ name: (w === 'function' ? word(k + 1) ?? '' : w).replace(/\(\)$/, ''), close: closer[fnBody]! < 0 ? n : closer[fnBody]! });
      functionEnd = Math.max(functionEnd, closer[fnBody]! < 0 ? n : closer[fnBody]!);
      k = fnBody;
      continue;
    }
    if (COND_KEYWORDS.has(w)) {
      inCondition = true;
      k++;
      continue;
    }
    if (BODY_KEYWORDS.has(w)) {
      inCondition = false;
      k++;
      continue;
    }
    if (END_KEYWORDS.has(w)) {
      cmd = false;
      k++;
      continue;
    }
    if (w === '!') {
      negateEnd = segEnd[k]!;
      k++;
      continue;
    }
    const name = basename(w);
    // P52 (a, b): whether this command keeps an `&&` chain unconditional; a call to a script function that can exit
    lastSafe = chainSafe(k, w);
    while (fnStack.length > 0 && fnStack[fnStack.length - 1]!.close <= k) fnStack.pop();
    if (exitFns.has(w) && !isDead(k)) afterCondExit = true;
    if (w === 'cd') {
      const target = word(k + 1);
      cwd = target === null || target === '' || target === '-' || /[$`~\\]/.test(target) || target.startsWith('/') ? null : resolveDir(cwd, target);
      cmd = false;
      k += target === null ? 1 : 2;
      continue;
    }
    if (w === 'set') {
      for (let j = k + 1; j < segEnd[k]!; j++) if (!isDead(k) && (toks[j]!.op === '$(' || /[$`]/.test(toks[j]!.w))) opaqueSet = true;
      if (!isDead(k) && segEnd[k]! < n && toks[segEnd[k]!]!.op === '$(') opaqueSet = true;
      for (let j = k + 1; j < segEnd[k]!; j++) {
        const f = toks[j]!.w;
        if (!(f.startsWith('-') || f.startsWith('+')) || f.startsWith('--') || f.length < 2) continue;
        const on = f[0] === '-';
        if (f.includes('e')) errexit = on;
        // P50 (C1): `set -n` / `set -o noexec` (any spelling): bash only reads what follows, it runs none of it
        if (on && /^-[a-zA-Z]*n/.test(f)) deadAfter = Math.min(deadAfter, k);
        if (f.endsWith('o')) {
          const opt = word(j + 1);
          if (opt === 'errexit') errexit = on;
          if (opt === 'pipefail') pipefail = on;
          if (opt === 'noexec' && on) deadAfter = Math.min(deadAfter, k);
        }
      }
      cmd = false;
      k++;
      continue;
    }
    if (name === 'command' && /^-[a-zA-Z]*[vV]/.test(word(k + 1) ?? '')) { // command -v X: only checks that X exists
      cmd = false;
      k++;
      continue;
    }
    // `exit` on its own in the step's top-level list (not in a group, a compound command, a function or a condition,
    // and not joined by && || | &): nothing after it runs
    // P52 (b): an exit/return that can end the script with success (no code, 0, or one pipegen can't read; a literal
    // non-zero code fails the run, never a silent pass): in a function body it marks the function; anywhere else but
    // the top-level list (a group, a subshell, if/case/loop, an &&/|| chain) every later run is under a condition
    if ((w === 'exit' || w === 'return') && !isDead(k) && !/^[1-9][0-9]{0,2}$/.test(word(k + 1) ?? '')) {
      const fn = fnStack.length > 0 && k < fnStack[fnStack.length - 1]!.close ? fnStack[fnStack.length - 1]! : null;
      if (fn !== null) exitFns.add(fn.name);
      else if (depth[k]! > 0 || condDepth[k]! > 0 || condChain || inCondition) afterCondExit = true;
    }
    if ((w === 'exit' || w === 'return') && depth[k] === 0 && !inCondition && k >= functionEnd && k > negateEnd
      && (k === 0 || toks[k - 1]!.op === ';' || toks[k - 1]!.op === '\n')
      && (segEnd[k]! >= n || toks[segEnd[k]!]!.op === ';' || toks[segEnd[k]!]!.op === '\n')) deadAfter = Math.min(deadAfter, k);
    match(k, w, name);
    const next = word(k + 1);
    const visit = (wrapper: boolean) => {
      const dead = isDead(k);
      onCmd?.({ name, args: argsAfter(k), dir: cwd, reason: shellReason(k), dead, wrapper, afterBin: binNext === k });
      if (!dead && !wrapper) lastCmd = { kind: OK_COMMANDS.has(name) ? 'ok' : name === 'false' ? 'fail' : 'other', start: k, end: segEnd[k]! };
    };
    if (name === 'docker' && next === 'run') {
      visit(false);
      let j = k + 2;
      for (let f = word(j); f !== null && f.startsWith('-'); f = word(j)) j += !f.includes('=') && DOCKER_VALUE_FLAGS.has(f) ? 2 : 1;
      const image = word(j);
      if (image !== null) match(j, image, imageName(image));
      containerEnd = segEnd[k]!;
      k = j + 1; // the container's command follows the image
      cmd = true;
      continue;
    }
    if (next !== null && SUB_WRAPPERS[name]?.includes(next)) {
      const j = skipFlags(k + 2, name);
      visit(j >= 0 && word(j) !== null);
      cmd = j >= 0; // a flag a strict wrapper doesn't know: no command follows
      k = j >= 0 ? j : k + 2;
      continue;
    }
    if (SHELLS.has(name)) {
      // P50 (C1): `bash|sh|zsh|dash [allowlisted flags] <script>`: any other flag (-n, --noexec, -o noexec, -c, one
      // pipegen doesn't know) and this command gives no coverage at all
      const j = shellFlagsEnd(k + 1);
      if (j < 0) {
        visit(false);
        cmd = false;
        k = segEnd[k]!;
        continue;
      }
      visit(word(j) !== null);
      shellScriptAt = j;
      cmd = true;
      k = j;
      continue;
    }
    if (WRAPPERS.has(name)) {
      const j = skipFlags(k + 1, name);
      visit(j >= 0 && word(j) !== null);
      cmd = j >= 0;
      k = j >= 0 ? j : k + 1;
      continue;
    }
    // `yarn eslint .` runs a package binary; `yarn run x` and `yarn test` run a script (no command word follows)
    const bin = BIN_RUNNERS.has(name) && next !== null && next !== 'run' && !(next === 'test' || OWN_NAME_RE.test(next));
    visit(bin);
    if (bin) binNext = k + 1;
    cmd = bin;
    k++;
  }
  return found;
}

/** A `uses: docker://image` step: the image name as a command, with `with.args` as its flags. */
export function scanImage(uses: string, w: Inputs, sigs: Compiled): Found[] {
  const name = imageName(uses.slice('docker://'.length));
  const args = inputWords(w, 'args');
  if (probeCall(args)) return [];
  const capped = inputWordsCapped(w, 'args');
  // Plan P Task 3: a signature's later command words come first in the args (`docker://aquasec/trivy` with `image …`)
  const starts = (words: readonly string[]) => words.every((x, i) => args[i] === x);
  return (sigs.byFirstWord.get(name) ?? []).filter((r) => starts(r.rest) && !r.excludes.some(starts) && flagsAllow(r.tool, args, !capped))
    .flatMap((r) => {
      const target = r.tool.scanTarget === undefined ? null : imageTarget(args.slice(r.rest.length));
      if (target !== null && target !== 'unknown' && target !== r.tool.scanTarget) return [];
      return [foundOf(r.tool, '.', inputsCrowded(r.tool, w, ['args']) || capped ? 'inputs' : (target === 'unknown' ? 'target' : commandReason(r.tool, args)),
        configTurnedOff(r.tool, args))];
    });
}

/**
 * Plan P Task 3 (PB3): grype's sources (https://oss.anchore.com/docs/reference/grype/cli/): image schemes, and the
 * schemes that read a folder, a file, an SBOM or package lists. `--from` picks the source behaviour too.
 */
const IMAGE_SCHEMES = ['docker:', 'podman:', 'docker-archive:', 'oci-archive:', 'oci-dir:', 'singularity:', 'registry:'];
const FOLDER_SCHEMES = ['dir:', 'file:', 'sbom:', 'purl:', 'cpes:', 'cpe:', 'pkg:', 'zarf:'];
const FOLDER_SOURCES: ReadonlySet<string> = new Set(['dir', 'file', 'sbom', 'purl', 'cpes', 'cpe', 'zarf']);
const REPO_PART_RE = /^[a-z0-9][a-z0-9._\/:-]{0,254}$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
/** An image reference with a :tag or an @sha256 digest (a registry host and port may come first). Single-class regexes only. */
function imageRef(w: string): boolean {
  const at = w.indexOf('@sha256:');
  if (at >= 0) return REPO_PART_RE.test(w.slice(0, at)) && /^[0-9a-f]{64}$/.test(w.slice(at + 8));
  const slash = w.lastIndexOf('/');
  const colon = w.indexOf(':', slash + 1);
  return colon > slash + 1 && REPO_PART_RE.test(w.slice(0, colon)) && TAG_RE.test(w.slice(colon + 1));
}
/**
 * Plan P Task 3 (PB3, `scanTarget`): what a scanner's arguments name. 'folder' when any word is a folder, file or SBOM
 * source (dir:, sbom:, `--from dir`, a path); else 'image' when one names an image (a scheme, or a reference with a
 * tag or digest); else 'unknown' (a variable, a bare name, nothing). A flag's value word is read like the others: it
 * can only make the answer 'folder' or leave it 'unknown', unless it looks like an image reference.
 */
function imageTarget(args: readonly string[]): 'image' | 'folder' | 'unknown' {
  let image = false;
  let unsure = false;
  for (let i = 0; i < args.length; i++) {
    const w = args[i] as string;
    const from = w === '--from' ? args[i + 1] : w.startsWith('--from=') ? w.slice('--from='.length) : undefined;
    if (from !== undefined && from.toLowerCase().split(',').some((x) => FOLDER_SOURCES.has(x.trim()))) return 'folder';
    // fix round 1 (review G1, G2): a flag's value is never the target (`--distro alpine:3.19`, `--file ./r.json`). A
    // flag pipegen doesn't know may take the next word as its value: an image or a path there can't be placed.
    if (w.startsWith('-') && !w.includes('=') && w.length > 1) {
      if (SCAN_VALUE_FLAGS.has(w)) i++;
      else if (!SCAN_BOOLEAN_FLAGS.has(w) && i + 1 < args.length && !(args[i + 1] as string).startsWith('-') && targetLike(args[i + 1] as string)) {
        unsure = true;
        i++;
      }
      continue;
    }
    if (w.startsWith('-') || w.length > 512 || !regexSafe(w)) continue;
    const lower = w.toLowerCase();
    if (FOLDER_SCHEMES.some((x) => lower.startsWith(x)) || w === '.' || w === '..' || w.startsWith('./') || w.startsWith('../') || w.startsWith('/')
      || w.startsWith('~') || w.includes('\\')) return 'folder';
    if (w.includes('$') || w.includes('`')) continue;
    if (IMAGE_SCHEMES.some((x) => lower.startsWith(x)) || imageRef(w)) image = true;
  }
  return image && !unsure ? 'image' : 'unknown';
}
/**
 * grype's flags that take a value, and its flags that don't
 * (https://github.com/anchore/grype/blob/main/cmd/grype/cli/options/grype.go and the root flags -c/--config, --profile,
 * -v, -q).
 */
const SCAN_VALUE_FLAGS: ReadonlySet<string> = new Set(['-s', '--scope', '-o', '--output', '--file', '--name', '--distro', '-t', '--template', '-f', '--fail-on',
  '--ignore-states', '--exclude', '--platform', '--from', '--vex', '-c', '--config', '--profile', '--sort-by']);
const SCAN_BOOLEAN_FLAGS: ReadonlySet<string> = new Set(['--add-cpes-if-none', '--only-fixed', '--only-notfixed', '--by-cve', '--show-suppressed', '-v', '-vv',
  '-vvv', '--verbose', '-q', '--quiet']);
/** A word that could be a scan target: an image reference or scheme, a folder scheme, or a path. */
function targetLike(w: string): boolean {
  if (w.length > 512 || !regexSafe(w)) return false;
  const lower = w.toLowerCase();
  return IMAGE_SCHEMES.some((x) => lower.startsWith(x)) || FOLDER_SCHEMES.some((x) => lower.startsWith(x)) || imageRef(w) || w.startsWith('.') || w.startsWith('/')
    || w.startsWith('~') || w.includes('\\');
}

// ---------- own scripts read from package.json (Task 5) ----------

/**
 * Fix round 3 (N7): a command that runs package scripts. `patterns`: script names or globs; `soft`: the runner can't fail
 * on them (npm-run-all -c, concurrently --success other than all); `unknown`: part of it is something pipegen can't
 * follow (an unknown flag, a plain command given to concurrently, a flag before the script name).
 * - npm: run, run-script, rum, urn <name>; test, t, tst (https://github.com/npm/cli/blob/latest/lib/utils/cmd-list.js).
 * - yarn | pnpm | bun: run <name>; test; lint[:x]; and `yarn|pnpm <name>` when that script exists (`scripts` given).
 * - npm-run-all, run-s, run-p: every non-flag argument is a script pattern; `*` stays inside one `:` part, `**`
 *   crosses them (https://github.com/mysticatea/npm-run-all/blob/master/docs/npm-run-all.md).
 * - concurrently: `npm:`, `yarn:`, `pnpm:` and `bun:` arguments name scripts (globs allowed).
 * After the name(s), a flag other than --silent, -s or --if-present (npm's --workspace, pnpm's --filter) is unknown.
 * `glob`: the patterns are npm-run-all / concurrently globs (npm, yarn, pnpm and bun take one literal name). Fix round 4
 * (N8): `capped` when a glob call names more than MAX_SCRIPT_PATTERNS patterns or one that fails SCRIPT_PATTERN_RE.
 */
interface ScriptCall { patterns: string[]; soft: boolean; unknown: boolean; glob: boolean; capped: boolean }
const NPM_RUN: ReadonlySet<string> = new Set(['run', 'run-script', 'rum', 'urn']);
const NPM_TEST: ReadonlySet<string> = new Set(['test', 't', 'tst']);
const RUN_ALL: ReadonlySet<string> = new Set(['npm-run-all', 'run-s', 'run-p']);
const RUN_ALL_FLAGS: ReadonlySet<string> = new Set(['-s', '--serial', '--sequential', '-p', '--parallel', '-l', '--print-label', '-n', '--print-name', '-r', '--race',
  '--silent', '--aggregate-output']);
const CONCURRENTLY_VALUED: ReadonlySet<string> = new Set(['-n', '--names', '--name-separator', '-c', '--prefix-colors', '-p', '--prefix', '-l', '--prefix-length',
  '-t', '--timestamp-format', '--default-input-target', '--restart-tries', '--restart-after', '-m', '--max-processes', '--kill-signal', '--hide']);
const CONCURRENTLY_BOOLEAN: ReadonlySet<string> = new Set(['-k', '--kill-others', '--kill-others-on-fail', '-r', '--raw', '--no-color', '-g', '--group', '-i',
  '--handle-input', '--pad-prefix', '-P', '--passthrough-arguments', '--timings']);
const SCRIPT_FLAGS_OK: ReadonlySet<string> = new Set(['--silent', '-s', '--if-present']);

export function scriptCall(name: string, args: readonly string[], scripts?: ReadonlyMap<string, string> | null): ScriptCall | null {
  const after = (from: number): boolean => { // unknown flags after the name(s), before `--`
    for (const w of args.slice(from)) {
      if (w === '--') return false;
      if (w.startsWith('-') && redirection(w) === null && !SCRIPT_FLAGS_OK.has(w)) return true;
    }
    return false;
  };
  const one = (pattern: string, from: number): ScriptCall => ({ patterns: [pattern], soft: false, unknown: after(from), glob: false, capped: false });
  /** Fix round 4 (N8): at most MAX_SCRIPT_PATTERNS globs, each matching SCRIPT_PATTERN_RE; anything else is capped. */
  const globs = (out: ScriptCall): ScriptCall => {
    if (out.patterns.length > MAX_SCRIPT_PATTERNS || !out.patterns.every((p) => SCRIPT_PATTERN_RE.test(p))) out.capped = true;
    return out;
  };
  const [a, b] = args;
  if (a === undefined) return null;
  if (name === 'npm') {
    if (NPM_TEST.has(a)) return one('test', 1);
    if (NPM_RUN.has(a) && b !== undefined && b !== '' && !b.startsWith('-')) return one(b, 2);
    return null;
  }
  if (PACKAGE_MANAGERS.includes(name)) {
    if (a === 'run' && b !== undefined && b !== '' && !b.startsWith('-')) return one(b, 2);
    if (a === 'test' || ownName(a)) return one(a, 1);
    if ((name === 'yarn' || name === 'pnpm') && scripts?.has(a) === true && !a.startsWith('-')) return one(a, 1);
    return null;
  }
  if (RUN_ALL.has(name)) {
    const out: ScriptCall = { patterns: [], soft: false, unknown: false, glob: true, capped: false };
    for (let i = 0; i < args.length; i++) {
      const w = args[i] as string;
      if (w === '--') break;
      if (w === '-c' || w === '--continue-on-error') out.soft = true;
      else if (w === '--max-parallel' || w === '--npm-path') i++;
      else if (w.startsWith('--max-parallel=') || w.startsWith('--npm-path=') || RUN_ALL_FLAGS.has(w)) continue;
      else if (w.startsWith('-')) out.unknown = true;
      else out.patterns.push(w.trim().split(/\s+/)[0] as string); // "build:* -- --watch": the task is the first word
    }
    return globs(out);
  }
  if (name === 'concurrently') {
    const out: ScriptCall = { patterns: [], soft: false, unknown: false, glob: true, capped: false };
    for (let i = 0; i < args.length; i++) {
      const w = args[i] as string;
      const eq = w.indexOf('=');
      const flag = eq > 0 ? w.slice(0, eq) : w;
      if (flag === '-s' || flag === '--success') {
        const v = eq > 0 ? w.slice(eq + 1) : args[++i];
        if (v !== 'all') out.soft = true;
      } else if (CONCURRENTLY_VALUED.has(flag)) i += eq > 0 ? 0 : 1;
      else if (CONCURRENTLY_BOOLEAN.has(w)) continue;
      else if (w.startsWith('-')) out.unknown = true;
      else {
        const m = /^(?:npm|yarn|pnpm|bun):(.+)$/.exec(w.trim());
        if (m) out.patterns.push((m[1] as string).split(/\s+/)[0] as string);
        else out.unknown = true; // a plain command: not followed
      }
    }
    return globs(out);
  }
  return null;
}

export const UNKNOWN_SCRIPT_CATEGORIES: readonly string[] = [...SCRIPT_CATEGORIES].map((c) => `${UNKNOWN_PREFIX}${c}`);
export const globCappedWhy = (subject: string) =>
  `${subject.charAt(0).toUpperCase()}${subject.slice(1)} runs package scripts by name pattern, more than pipegen follows (at most ${MAX_SCRIPT_PATTERNS} patterns of up to 64 characters, fewer than ${MAX_SCRIPT_TARGETS} matching scripts, and a cap on matching work), so pipegen can't tell what they run.`;
