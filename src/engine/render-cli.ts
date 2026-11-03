// The CLI kinds of the step renderer (Plan B Task 6, sub-task 6b): release binaries, docker images, npm tools and pip
// tools become `run:` steps. This is the most injection-prone code in pipegen, so every string is hostile until proven
// otherwise, and the rules are few and mechanical:
// - The shell text is built from reviewed constants only. A constant is bare when it matches BARE_RE and single-quoted
//   otherwise (ruling S5); one that holds `${{` is refused (Actions evaluates it even inside quotes). A value the AI
//   chose never appears in the shell text: it travels in a step env variable `PIPEGEN_ARG_<n>` and is written as
//   "$PIPEGEN_ARG_<n>", also inside a word.
// - Every third-party tool runs by absolute path under `/usr/bin/env -i` with an explicit allowlist (ruling S6): HOME, a
//   fixed PATH, RUNNER_TEMP, TMPDIR, the template env, PIPEGEN_ARG_n and, for a tool that runs the app, its declared
//   secrets. So job-level variables (NODE_OPTIONS, COVERAGE_RCFILE, TRIVY_*, …) and the step's own PIPEGEN_CONFIG never
//   reach it. No step writes $GITHUB_ENV or $GITHUB_PATH; every run step sets `shell: bash`, `BASH_ENV: ''`, `ENV: ''`.
// - Declared secrets reach only steps that run the app (tests, coverage); a scanner or linter refuses a spec that has
//   any (review R1-7), so the secret-name blocklist is a backstop and not the only guard.
// - Installs are verified before anything runs: a release asset by its sha256 (from env) before it is extracted, a docker
//   image by digest, an npm tool and its plugins by the exact version and integrity in the lockfile (ruling B5), a pip tool
//   only from a reviewed hash-locked closure (none exists yet, so pip is "not available yet").
// - The result file is checked before and after the tool, and moved under `$RUNNER_TEMP/pipegen-raw/<artifact>/` (ruling S7;
//   Plan C ruling B1: the raw result is never uploadable, only the gate's scrub writes `pipegen-out`). An exit code in
//   `{0} ∪ findingsExit` (ruling B2, ArgvPolicy) with a regular result file is a successful scan; any other exit deletes the result.
// - The pinned config is written from an env variable with `printf '%s'`, never a heredoc, to a file name the argv policy
//   chose (ruling S4). The repo's own config files are never named.
// - Rule archives (semgrep rules, nuclei templates) are fetched by commit and checked by tree (ruling S12), and the values a
//   tool needs at run time (image, local URL, Dockerfile, base ref) are slots from the render context (ruling B6): slots.ts.
// Nothing here uploads (ruling B3).
import { isDeepStrictEqual } from 'node:util';
import { ArtifactNameError, RANGE_CANARY_FILES, RANGE_FACTS_FILE, resultArtifactName, SECRETS_RANGE_ARTIFACT } from './artifact-names.js';
import { ASSET_RE, COMMIT_SHA_RE, DIGEST_RE, isGitHubRepo, isNpmName, isPypiName, parseImageRef, pep503, SHA256_RE, SRI_SHA512_RE, TAG_RE } from './names.js';
import { closureRootDependencies, loadNpmClosure, NpmClosureError, pinOk, type NpmPin } from './npm-closure.js';
import { EXPR, own, refuse, show } from './render-error.js';
import type { RenderContext, RenderedStep, RenderResult } from './render-step.js';
import { slotProblem, type SlotKind } from './slots.js';
import { ARGV_POLICIES, PIP_CLOSURES, PLAIN_REL_RE, RANGE_STEP_ENV, RANGE_TOOL, rangeScanStepId, runsRepoCode, sha16, TEST_COMMANDS, type ArgvPolicy } from './tool-flags.js';

export { sha16 };   // defined in tool-flags.ts (the job rules need it too); re-exported for the callers that import it from here
import { EXTRA_RULES_AT, tuningEffects, type TuningEffects } from './tuning.js';
import type { InstallSpec, ReviewedTool, Service, StepSpec } from '../types.js';

/** Test and internal hooks: the argv policies and the pip closures the renderer reads (production passes neither). */
export interface RenderOptions {
  policies?: Readonly<Record<string, ArgvPolicy>>;
  pipClosures?: Readonly<Record<string, string>>;
  /** npm closure locks by entry id, instead of data/npm-closures/ (tests). A lock is judged the same either way. */
  npmClosures?: Readonly<Record<string, string>>;
  /** Where rule and template archives are fetched from (default `https://github.com/`, with only the https protocol). A test points it at a local bare repo (`file:///…/`). */
  gitBase?: string;
}

/** What the CLI renderer needs from render-step.ts (which owns the platform actions and the secret-name rules). */
export interface CliHooks {
  /** The setup-node step for a service's own Node version text (mapped, never rendered raw). */
  setupNode(runtimeVersion: string | undefined): RenderedStep;
  setupPython(): RenderedStep;
  isDangerousName(name: string): boolean;
}

export interface CliArgs { spec: StepSpec; tool: ReviewedTool; service: Service | undefined; ctx: RenderContext; hooks: CliHooks; options: RenderOptions }

// ---------- shell text ----------

/** A word that needs no quoting. Plain letters, digits and `_@%+=:,./-`: nothing the shell, a glob or a tilde reads. */
const BARE_RE = /^[A-Za-z0-9_@%+=:,./-]+$/;
const FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,99}$/;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
const EXE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
const PLAIN_OUT_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
const CONFIG_FLAG_RE = /^-{1,2}[A-Za-z][A-Za-z0-9-]{0,40}$/;
const PLACEHOLDER_SPLIT = /(\{[A-Za-z_][A-Za-z0-9_-]{0,63}\})/;
const CHOICE_FLAG_RE = /^[a-z][a-z0-9-]{0,40}$/;
const MAX_TEXT = 64 * 1024;
/** Tool categories that run the project's own code (tests, coverage, image builds): the only steps a declared secret may reach. */
export const APP_RUNNING_CATEGORIES: ReadonlySet<string> = new Set(['coverage', 'unit-tests', 'full-tests', 'image-build']);
/** Names the renderer itself puts in a step's env or in the tool's environment; a template env may not use them. */
const RESERVED_ENV = /^(?:HOME|PATH|RUNNER_TEMP|TMPDIR|BASH_ENV|ENV|PIPEGEN_(?:CONFIG|TUNED_CONFIG|IMAGE|DL_.*|NPM_EXPECT|REQUIREMENTS|RULES_(?:REMOTE|COMMIT|TREE_WANT)|ARG_\d+))$/;


/** A reviewed constant as a shell word: bare when plain, else single-quoted (`'` becomes `'\''`). `${{` and NUL are refused. */
function q(s: string): string {
  if (s.includes(EXPR)) return refuse('A reviewed command holds an expression (${{), which Actions would evaluate; pipegen refuses it.');
  if (s.includes('\0')) return refuse('A reviewed command holds a NUL character.');
  return BARE_RE.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

const script = (lines: readonly string[]): string => lines.join('\n');
/** The first lines of every script: fail on any error or unset name, no CDPATH (it redirects `cd`), and a message helper. */
const HEAD = ['set -euo pipefail', 'unset CDPATH', 'pg_fail() { echo "pipegen: $1" >&2; exit 1; }'] as const;
/** The system tools of a script (mkdir, mv, chmod, wc, …) are looked up in these folders only, never in a PATH an earlier step changed. */
const FIX_PATH = `PATH=${FIXED_PATH}`;

/** A run step: bash, and the two startup-file variables empty so no ambient file runs before the script (ruling S6). */
function runStep(name: string, run: string, env: Record<string, string>, id?: string): RenderedStep {
  return { ...(id === undefined ? {} : { id }), name, run, shell: 'bash', env: { BASH_ENV: '', ENV: '', ...env } };
}

/** `cd` into the service folder after checking every part is a real folder (no symlink) and the result is inside the workspace (ruling S8, run-time half). */
function cdLines(workingDir: string | undefined): string[] {
  if (workingDir === undefined) return [];
  if (!PLAIN_REL_RE.test(workingDir)) return refuse(`The working folder ${show(workingDir)} is not a plain folder.`);
  const parts = workingDir.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.length === 0) return [];
  const prefixes = parts.map((_, i) => parts.slice(0, i + 1).join('/'));
  return [
    `for d in ${prefixes.map(q).join(' ')}; do`,
    '  if [ -L "$d" ] || [ ! -d "$d" ]; then pg_fail "the folder $d is not a real folder inside the repository"; fi',
    'done',
    `cd -- ${q(`./${parts.join('/')}`)}`,
    'ws="$(cd "$GITHUB_WORKSPACE" && pwd -P)"',
    'case "$(pwd -P)" in "$ws"/*) ;; *) pg_fail "the working folder is outside the repository" ;; esac',
  ];
}

/**
 * The `env -i` array: the only variables a tool sees (ruling S6). `names` are passed through from the step's env by name;
 * `constants` are reviewed `NAME=value` words written into the script itself (so no job or step variable can change them).
 */
function allowlist(pathValue: string, names: readonly string[], constants: readonly string[] = [], dynamic: readonly string[] = []): string[] {
  for (const c of constants) if (!/^[A-Z][A-Z0-9_]{0,40}=[A-Za-z0-9_.-]{0,40}$/.test(c)) refuse('A constant of the tool environment is not a plain NAME=value.');
  return [
    'pg_env=(',
    '  /usr/bin/env -i',
    '  "HOME=$home"',
    `  "PATH=${pathValue}"`,
    '  "RUNNER_TEMP=$RUNNER_TEMP"',
    '  "TMPDIR=$RUNNER_TEMP"',
    ...constants.map((c) => `  "${c}"`),
    ...dynamic.map((d) => `  "${d}"`),
    ...names.map((n) => `  "${n}=$${n}"`),
    ')',
  ];
}

/**
 * The start of every script: the head, optional discovery of a tool the setup step installed (it needs the ambient PATH,
 * so it comes before PATH is fixed), the fixed PATH, a fresh HOME, and `sys`, the prefix the system tools (curl, tar,
 * find, sha256sum, docker) run under: `env -i` with a fixed PATH, so no environment variable of the job reaches them
 * (TAR_OPTIONS, CURL_HOME, …; review finding 6). `node` is checked to be the major setup-node was asked for.
 */
function prologue(artifact: string, opts: { discover?: readonly string[]; nodeMajor?: string } = {}): string[] {
  return [
    ...HEAD,
    ...(opts.nodeMajor === undefined ? [] : NODE_DISCOVERY),
    ...(opts.discover ?? []),
    FIX_PATH,
    `home="$RUNNER_TEMP/pipegen-home/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-home" "$home"',
    'sys=(',
    '  /usr/bin/env -i',
    `  "PATH=${FIXED_PATH}"`,
    '  "HOME=$home"',
    ')',
    ...(opts.nodeMajor === undefined ? [] : [
      `case "$("\${sys[@]}" "$node" --version)" in v${opts.nodeMajor}.*) ;; *) pg_fail "the node on PATH is not version ${opts.nodeMajor}, which the Node setup step installed" ;; esac`,
    ]),
  ];
}

/** Where `node` comes from: the folder setup-node put on PATH, read before PATH is fixed (no dirname: the folder is cut off with a parameter expansion). */
const NODE_DISCOVERY = [
  'node="$(command -v node || true)"',
  '[ -n "$node" ] || pg_fail "node was not found; the Node setup step must run first"',
  'nodebin="${node%/*}"',
] as const;

// ---------- checks on the entry ----------

/** The template env (step.cli.env, equal to fixedInputs.env), each name and value checked. */
function templateEnv(tool: ReviewedTool, hooks: CliHooks): Record<string, string> {
  const env = { ...(tool.step.cli?.env ?? {}) };
  for (const [k, v] of Object.entries(tool.fixedInputs.env ?? {})) {
    if (env[k] !== v) refuse(`The reviewed entry ${show(tool.id)} has an env that disagrees with its fixed inputs.`);
  }
  for (const [k, v] of Object.entries(env)) {
    // PIPEGEN_* names are the renderer's own family (the rules archives use them); everything else must be harmless to pass on
    const dangerous = !k.startsWith('PIPEGEN_') && hooks.isDangerousName(k);
    if (!NAME_RE.test(k) || k !== k.toUpperCase() || RESERVED_ENV.test(k) || dangerous) {
      refuse(`The reviewed env name ${show(k)} can't be passed to a tool: it is reserved by the renderer or changes how code runs.`);
    }
    if (typeof v !== 'string' || v.includes(EXPR) || v.includes('\0')) refuse(`The reviewed env value of ${show(k)} can't be written into a workflow.`);
  }
  return env;
}

interface PinnedConfig { flag: string; content: string; fileName: string }

/** The pinned config of an entry, cross-checked with its reviewed policy. Null when neither has one. */
function configOf(tool: ReviewedTool, pol: ArgvPolicy): PinnedConfig | null {
  const fx = tool.fixedInputs.config;
  if (fx === undefined) return pol.config === undefined ? null : refuse(`The reviewed entry ${show(tool.id)} lost the pinned config its argv policy requires.`);
  if (!('flag' in fx.passAs)) return refuse(`The pinned config of ${show(tool.id)} is passed as an input, which only an action takes; pipegen passes a cli config as a flag.`);
  if (typeof fx.content !== 'string' || fx.content.includes(EXPR)) return refuse(`The pinned config of ${show(tool.id)} holds an expression (\${{), which Actions would evaluate.`);
  if (fx.content.includes('\0') || fx.content.length > MAX_TEXT) return refuse(`The pinned config of ${show(tool.id)} is not plain text of at most 64 KiB.`);
  const p = pol.config;
  if (p === undefined || p.flag !== fx.passAs.flag || p.content !== fx.content) return refuse(`The pinned config of ${show(tool.id)} differs from the one its argv policy reviewed.`);
  if (typeof p.fileName !== 'string' || !FILE_NAME_RE.test(p.fileName)) return refuse(`The argv policy of ${show(tool.id)} gives its config a file name that is not plain.`);
  if (!CONFIG_FLAG_RE.test(p.flag)) return refuse(`The config flag of ${show(tool.id)} is not a plain flag.`);
  return { flag: p.flag, content: fx.content, fileName: p.fileName };
}

function checkInstall(tool: ReviewedTool, pol: ArgvPolicy): InstallSpec {
  const cli = tool.step.cli;
  if (cli === undefined) return refuse(`${show(tool.id)} has no command to run.`);
  if (cli.install.method !== pol.method || cli.install.package !== pol.package) {
    return refuse(`The install of ${show(tool.id)} (${cli.install.method} ${show(cli.install.package)}) is not the one its argv allowlist was reviewed for (${pol.method} ${show(pol.package)}).`);
  }
  if (cli.install.version !== tool.candidate.version) return refuse(`The install version of ${show(tool.id)} is not the reviewed version of its candidate.`);
  if (typeof pol.exe !== 'string' || !EXE_RE.test(pol.exe)) return refuse(`The executable of ${show(tool.id)} is not a plain file name.`);
  // the binary that runs is the one the entry's command names (the loader checks this too; an injected policy must not change it)
  if (cli.command[0] !== pol.exe) return refuse(`The command of ${show(tool.id)} starts with ${show(cli.command[0])}, not its reviewed executable ${show(pol.exe)}.`);
  return cli.install;
}

// ---------- the command ----------

interface Words { env: Record<string, string>; index: Map<string, number> }

/** The chosen value of a choice (the first listed one when the spec gave none), checked against the entry's list. */
function chosenValue(tool: ReviewedTool, spec: StepSpec, name: string): string {
  const offered = own(tool.choices, name);
  if (offered === undefined) return refuse(`The command of ${show(tool.id)} names a choice ${show(name)} that the entry does not offer.`);
  const value = own(spec.choices, name) ?? offered[0];
  if (typeof value !== 'string' || !offered.includes(value)) return refuse(`The choice ${show(name)} of ${show(tool.id)} has no allowed value.`);
  if (value.includes(EXPR)) return refuse(`The value of the choice ${show(name)} holds an expression (\${{), which Actions would evaluate.`);
  if (value.includes('\0')) return refuse(`The value of the choice ${show(name)} holds a NUL character.`);
  return value;
}

/** `"$PIPEGEN_ARG_n"` for a choice, allocating its env variable the first time the choice is used. */
function argVar(w: Words, name: string, value: string): string {
  let n = w.index.get(name);
  if (n === undefined) {
    n = w.index.size;
    w.index.set(name, n);
    w.env[`PIPEGEN_ARG_${n}`] = value;
  }
  return `"$PIPEGEN_ARG_${n}"`;
}

/** One template word as a shell word: constants quoted, `{choice}` placeholders (also inside a word) as quoted variables. */
function wordOf(word: string, tool: ReviewedTool, spec: StepSpec, w: Words): string {
  const out = word.split(PLACEHOLDER_SPLIT).map((part, i) => {
    if (i % 2 === 1) {
      const name = part.slice(1, -1);
      return argVar(w, name, chosenValue(tool, spec, name));
    }
    return part === '' ? '' : q(part);
  }).join('');
  return out === '' ? "''" : out;
}

const isBoolChoice = (values: readonly string[]): boolean => values.length === 2 && values.includes('false') && values.includes('true');

interface Built { main: string[]; then: string[][]; env: Record<string, string>; /** `"$PIPEGEN_ARG_n"` of the archive sub-folder choice */ sub?: string; /** repo-path slot variables (checked at run time) */ paths: string[]; fullHistory: boolean }

/**
 * The words after the executable, as shell words: placeholders become quoted env variables, the pinned config flag goes
 * right after the leading subcommand words (a Go or urfave tool stops reading flags at the first plain word), and a
 * dedicated tool's choices are appended as `--<choice> "$V"` (a bool choice `--<choice>="$V"`).
 */
function buildWords(tool: ReviewedTool, spec: StepSpec, pol: ArgvPolicy, config: PinnedConfig | null, configPath: string | null, slots: Slot[], tuned: TuningEffects): Built {
  const cli = tool.step.cli as NonNullable<typeof tool.step.cli>;
  const w: Words = { env: {}, index: new Map() };
  const rest = cli.command.slice(1);
  let lead = 0;
  while (lead < rest.length && !(rest[lead] as string).startsWith('-') && !PLACEHOLDER_SPLIT.test(rest[lead] as string)) lead++;
  if (pol.dedicated !== true && !isDeepStrictEqual(rest.slice(0, lead), pol.sub)) refuse(`The subcommand of ${show(tool.id)} is not the one its argv policy reviewed.`);
  const main = rest.map((x) => wordOf(x, tool, spec, w));
  // a slot: the value of a flag that the command already has is replaced; otherwise `flag value` (or just the value) goes last
  const paths: string[] = [];
  let fullHistory = false;
  for (const sl of slots) {
    const v = argVar(w, `slot:${sl.key}`, sl.value);
    if (sl.kind === 'repo-path') paths.push(v);
    if (sl.kind === 'git-ref') fullHistory = true;
    if (sl.key === '') { main.push(v); continue; }
    const at = rest.indexOf(sl.key);
    if (at >= 0 && at + 1 < rest.length) main[at + 1] = v;
    else main.push(q(sl.key), v);
  }
  // the archive folder: a tool run on the runner is told the checked-out folder where the reviewed command names its directory
  if (pol.archive !== undefined && pol.method !== 'docker') {
    let hit = 0;
    rest.forEach((x, i) => { if (x === pol.archive?.dir) { main[i] = '"$rules"'; hit++; } });
    if (hit === 0) return refuse(`The command of ${show(tool.id)} does not name its rules folder ${show(pol.archive.dir)}.`);
  }
  if (config !== null && configPath !== null) main.splice(lead, 0, q(config.flag), configPath);
  // per-repo tuning flags (6d) go in the same place, before the config flag and every other word: a Go or urfave tool stops reading
  // flags at the first plain word. A value picked from an enum travels in an env variable like every run-time value; a reviewed
  // constant (a rule folder inside the container) is written as a quoted word.
  const tuning: string[] = [];
  for (const fl of tuned.flags) tuning.push(q(fl.flag), fl.literal === true ? q(fl.value) : argVar(w, fl.key, fl.value));
  main.splice(lead, 0, ...tuning);
  const then = (cli.then ?? []).map((cmd) => {
    if (cmd[0] !== pol.exe) refuse(`A follow-up command of ${show(tool.id)} does not run its own executable.`);
    return cmd.slice(1).map((x) => wordOf(x, tool, spec, w));
  });
  let sub: string | undefined;
  for (const [name, values] of Object.entries(tool.choices)) {
    if (pol.archive?.subChoice === name) {
      if (!/^[a-z][a-z0-9-]{0,30}$/.test(chosenValue(tool, spec, name))) return refuse(`The rules folder ${show(name)} of ${show(tool.id)} is not a plain folder name.`);
      sub = argVar(w, name, chosenValue(tool, spec, name));
      continue;
    }
    if (w.index.has(name)) continue;
    if (pol.dedicated !== true) return refuse(`The choice ${show(name)} of ${show(tool.id)} has no place in its command (only a {${name}} placeholder may take it).`);
    if (!CHOICE_FLAG_RE.test(name)) return refuse(`The choice ${show(name)} of ${show(tool.id)} is not a plain flag name.`);
    const v = argVar(w, name, chosenValue(tool, spec, name));
    if (isBoolChoice(values)) main.push(`--${name}=${v}`);
    else main.push(`--${name}`, v);
  }
  return { main, then, env: w.env, ...(sub === undefined ? {} : { sub }), paths, fullHistory };
}


// ---------- slots (ruling B6) ----------

interface Slot { key: string; kind: SlotKind; value: string }

/** The slot values of an entry, from the render context and the profile only, each checked by slots.ts. */
function slotsOf(tool: ReviewedTool, pol: ArgvPolicy, service: Service | undefined, ctx: RenderContext, spec: StepSpec): Slot[] {
  const out: Slot[] = [];
  for (const [key, kind] of Object.entries(pol.slots ?? {})) {
    let value: string | undefined;
    let what: string;
    if (kind === 'image-digest') { value = ctx.targets?.image; what = 'the image to scan (an image target)'; }
    else if (kind === 'local-url') { value = ctx.targets?.url; what = 'the URL of the running app (a url target)'; }
    else if (kind === 'git-ref') { value = `origin/${ctx.profile.defaultBranch}`; what = 'the base ref'; }
    else if (pol.repoPathFrom === 'dockerfile') { value = service?.dockerfile; what = "the service's Dockerfile"; }
    else { value = ctx.targets?.k8sDir ?? (ctx.profile.repoFiles.kubernetes ? '.' : undefined); what = 'a folder of Kubernetes files (the repository has none and no folder was given)'; }
    if (value === undefined) return refuse(`${show(tool.id)} needs ${what}, which the render context does not have.`);
    const problem = slotProblem(kind, value, { defaultBranch: ctx.profile.defaultBranch });
    if (problem !== null) return refuse(`${what} for ${show(tool.id)} can't be used: ${problem}.`);
    // a repo path is relative to the repository root; the step runs in the service folder when it has one
    if (kind === 'repo-path' && spec.workingDir !== undefined) return refuse(`${show(tool.id)} takes a path relative to the repository root, so it can not run in a service folder.`);
    out.push({ key, kind, value });
  }
  return out;
}

// ---------- rule archives (ruling S12) ----------

const GIT_BASE = 'https://github.com/';

/** The reviewed commit of an archive: from its own env value, or from the archive URL that holds it. */
function archiveCommit(tool: ReviewedTool, a: NonNullable<ArgvPolicy['archive']>, env: Record<string, string>): string {
  let commit: string | undefined;
  if (a.commitEnv !== undefined) commit = env[a.commitEnv];
  else if (a.urlEnv !== undefined) commit = /\/archive\/([0-9a-f]{40})\.tar\.gz$/.exec(env[a.urlEnv] ?? '')?.[1];
  if (commit === undefined || !COMMIT_SHA_RE.test(commit)) return refuse(`${show(tool.id)} has no pinned 40-character commit for its rules.`);
  return commit;
}

/**
 * One step that fetches a pinned git archive and refuses it unless it is exactly the reviewed one: `git init` in a fresh
 * folder under runner temp; `git fetch --depth 1 <remote> <commit>`; `git checkout FETCH_HEAD`; HEAD must be the commit and
 * HEAD^{tree} the reviewed tree (the tree also catches GitHub serving a fork's objects under the upstream name). git runs
 * under `env -i` with a fixed PATH and a fresh HOME, no system or global config, and only the https protocol, so no repo
 * or user git configuration and no GIT_* variable is read. Then `.git` is removed and the folder is made read-only (a speed
 * bump; semgrep mounts it `:ro`). The archive's sha256 in the data is not used here: GitHub archives are not byte-stable, and
 * the tree check is the stronger one. Any failure fails the step; there is no fallback.
 */
function rulesStep(tool: ReviewedTool, a: NonNullable<ArgvPolicy['archive']>, artifact: string, env: Record<string, string>, base: string): RenderedStep {
  if (!isGitHubRepo(a.repo)) return refuse(`The rules repo of ${show(tool.id)} is not a GitHub owner/name.`);
  const tree = env[a.treeEnv];
  if (tree === undefined || !COMMIT_SHA_RE.test(tree)) return refuse(`${show(tool.id)} has no pinned 40-character git tree for its rules.`);
  const commit = archiveCommit(tool, a, env);
  const protocol = /^([a-z]+):\/\//.exec(base)?.[1];
  if (protocol !== 'https' && protocol !== 'file') return refuse('The rules remote is neither https nor file.');
  const lines = [
    ...prologue(artifact),
    `rules="$RUNNER_TEMP/pipegen-rules/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-rules"',
    'mkdir "$rules"',
    'git=(',
    '  /usr/bin/env -i',
    `  "PATH=${FIXED_PATH}"`,
    '  "HOME=$home"',
    '  GIT_CONFIG_NOSYSTEM=1',
    '  GIT_CONFIG_GLOBAL=/dev/null',
    '  GIT_TERMINAL_PROMPT=0',
    `  GIT_ALLOW_PROTOCOL=${protocol}`,
    '  /usr/bin/git',
    ')',
    'cd -- "$rules"',
    '"${git[@]}" init --quiet --template=',
    '"${git[@]}" fetch --quiet --depth 1 -- "$PIPEGEN_RULES_REMOTE" "$PIPEGEN_RULES_COMMIT"',
    '"${git[@]}" checkout --quiet FETCH_HEAD',
    '[ "$("${git[@]}" rev-parse HEAD)" = "$PIPEGEN_RULES_COMMIT" ] || pg_fail "the fetched commit is not the reviewed one"',
    '[ "$("${git[@]}" rev-parse \'HEAD^{tree}\')" = "$PIPEGEN_RULES_TREE_WANT" ] || pg_fail "the fetched tree is not the reviewed one"',
    'rm -rf -- "$rules/.git"',
    // a speed bump, not a guard (review-6b-r2 C3)
    'chmod -R a-w "$rules"',
  ];
  return runStep(`pipegen: fetch the ${a.repo.split('/')[1]} rules (pinned commit and tree)`, script(lines), {
    PIPEGEN_RULES_REMOTE: `${base}${a.repo}`, PIPEGEN_RULES_COMMIT: commit, PIPEGEN_RULES_TREE_WANT: tree,
  }, `tool-install-${sha16(`rules:${artifact}`)}`);
}

// ---------- explicit file lists (ArgvPolicy.fileList) ----------

export { OXLINT_EXTENSIONS } from './tool-flags.js';

/**
 * Shell lines that write the NUL-separated list of the regular tracked files with these extensions to `list` (a quoted shell word):
 * `git ls-files -z -s -- .` gives `mode sha stage<TAB>path`; only modes 100644 and 100755 are kept (a link is 120000, a submodule 160000);
 * extensions are compared in lower case. Runs inside the step's folder; `sys` is the clean-env array of the prologue.
 */
export function fileListLines(extensions: readonly string[], list: string): string[] {
  if (extensions.length === 0 || !extensions.every((e) => /^[a-z][a-z0-9]{0,9}$/.test(e))) throw new Error('the extensions of a file list are plain words');
  return [
    '"${sys[@]}" git ls-files -z -s -- . | while IFS= read -r -d \'\' rec; do',
    '  mode="${rec%% *}"',
    '  path="${rec#*$\'\\t\'}"',
    '  case "$mode" in 100644|100755) ;; *) continue ;; esac',
    `  case "\${path,,}" in ${extensions.map((e) => `*.${e}`).join('|')}) printf '%s\\0' "$path" ;; esac`,
    `done > ${list}`,
  ];
}
/** The run lines for a file list: nothing to lint is "0 files checked" (a notice, success); otherwise the tool runs through xargs, `--` before the files; its exit code (xargs gives 123 when a batch failed) is kept in rc. */
export function fileListRun(launch: string, list: string): string[] {
  return [
    `if [ ! -s ${list} ]; then`,
    '  echo "pipegen: 0 files to check (this folder has no tracked file the tool reads)"',
    '  echo "::notice::the tool checked 0 files"',
    'else',
    `  xargs -0 -r -a ${list} ${launch} -- || rc=$?`,
    'fi',
  ];
}

// ---------- the main entry ----------

/** The text a run line starts a tool with: the env -i array, then the launcher. The referee finds trivy's launch by these (final review minor 10), so a change here changes its check too. */
const LAUNCH_ENV = '"${pg_env[@]}"';
/** The launcher of a downloaded release binary. */
const releaseLauncher = (exe: string): string => `"$bin/${exe}"`;
/** The line a rendered trivy run step starts trivy with. */
export const TRIVY_LAUNCH_RE = new RegExp(`${LAUNCH_ENV} ${releaseLauncher('trivy')}`.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'));
/** Tool categories of the DAST steps: the only docker steps that may use the host network (their target is the app on the runner). */
const DAST_CATEGORIES: ReadonlySet<string> = new Set(['dast', 'api-dast']);

export function renderCliTool({ spec, tool, service, ctx, hooks, options }: CliArgs): RenderResult {
  const policies = options.policies ?? ARGV_POLICIES;
  const cli = tool.step.cli;
  if (cli === undefined || tool.candidate.kind === 'action') return refuse(`${show(tool.id)} is not a cli entry.`);
  const pol = own(policies, tool.id);
  if (pol === undefined) return refuse(`${show(tool.id)} has no reviewed argv allowlist, so pipegen won't run it.`);
  if (pol.entrypoint === true) return refuse(`${show(tool.id)} is a job service (the image runs its own entrypoint), not a step; the job composer starts it.`);
  if (pol.needsSlot !== undefined) return refuse(`${show(tool.id)} ${pol.needsSlot}.`);
  const install = checkInstall(tool, pol);

  const secrets = spec.secrets ?? [];
  if (secrets.length > 0 && !tool.categories.some((c) => APP_RUNNING_CATEGORIES.has(c))) {
    return refuse(`${show(tool.id)} is a scanner or linter: declared secrets reach only steps that run the app (tests, builds), never a scanner, linter or upload step.`);
  }
  let artifact: string;
  try {
    artifact = resultArtifactName(spec.needId, spec.service, ctx.base === true ? { base: true } : undefined);
  } catch (e) {
    if (e instanceof ArtifactNameError) return refuse(e.message);
    throw e;
  }
  const out = tool.step.output.path === '' ? null : tool.step.output.path;
  if (out !== null && !PLAIN_OUT_RE.test(out)) return refuse(`The result path ${show(out)} of ${show(tool.id)} is not a plain file name.`);

  const kind = pol.method;
  const exe = pol.exe;
  const mount = pol.mount;
  if (kind === 'docker' && (mount === undefined || !/^\/[A-Za-z0-9._/-]{1,100}$/.test(mount.at))) return refuse(`${show(tool.id)} is a docker entry with no reviewed mount, so pipegen won't run it.`);
  const inWork = kind === 'docker' && mount?.source === 'work';
  const checker = kind === 'npm' && pol.runsRepoCode !== true;
  // where the pinned config lives: the isolated npm folder, the docker work folder, or a config folder of its own
  const cfgBase = checker ? '$npmdir' : inWork ? '$work' : '$cfg';

  const config = configOf(tool, pol);
  // where the tool finds its config: a file on the runner, the work folder's own file (ZAP reads -c there), or a read-only mount
  const configPath = config === null ? null : kind !== 'docker' ? `"${cfgBase}/${config.fileName}"` : inWork ? q(config.fileName) : q(`/pipegen-cfg/${config.fileName}`);
  const slots = slotsOf(tool, pol, service, ctx, spec);
  const tuned = tuningEffects(spec, tool, ctx);
  const built = buildWords(tool, spec, pol, config, configPath, slots, tuned);
  const tplEnv = templateEnv(tool, hooks);

  const env: Record<string, string> = { ...tplEnv, ...built.env };
  const archive = pol.archive;
  const passed: string[] = Object.keys(env);   // handed to the tool by name through the allowlist
  if (config !== null) env.PIPEGEN_CONFIG = config.content;
  // a generated config (lefthook's hooks, 6d) is written next to the run in a folder of its own; only a plain release-binary step with no pinned config takes one
  const tunedCfg = tuned.generatedConfig;
  if (tunedCfg !== null) {
    if (kind !== 'github-release' || config !== null || !FILE_NAME_RE.test(tunedCfg.fileName) || !NAME_RE.test(tunedCfg.envName) || tunedCfg.content.includes(EXPR) || tunedCfg.content.includes('\0') || tunedCfg.content.length > MAX_TEXT) {
      return refuse(`${show(tool.id)} can not take a generated config.`);
    }
    env.PIPEGEN_TUNED_CONFIG = tunedCfg.content;
  }
  if (tuned.extraRules.length > 0 && (archive === undefined || kind !== 'docker')) return refuse(`${show(tool.id)} has no rules archive to add rule folders from.`);
  for (const name of secrets) {
    if (!NAME_RE.test(name) || hooks.isDangerousName(name)) return refuse(`The secret name ${show(name)} can't be passed to a tool.`);
    env[name] = `\${{ secrets.${name} }}`;
    passed.push(name);
  }

  const steps: RenderedStep[] = [];
  const vars: string[] = [];           // names the run line uses
  const closureVars: string[] = [];    // variables that point into the install folder
  const afterAllow: string[] = [];     // lines that need the env -i array
  const installLines: string[] = [];   // a checker's install from the closure, before anything else touches its folder
  const prep: string[] = [];           // folders to create
  let nodeMajor: string | undefined;
  let prefix: string;                  // the launcher: what comes right before the tool's own words
  let pathValue = FIXED_PATH;

  if (kind === 'github-release') {
    steps.push(releaseInstall(tool, install, exe, artifact));
    vars.push(`bin="$RUNNER_TEMP/pipegen-bin/${artifact}"`);
    prefix = releaseLauncher(exe);
  } else if (kind === 'docker') {
    const image = imageOf(tool, install);
    steps.push(runStep(`pipegen: pull the ${exe} image`, script([...prologue(artifact), '"${sys[@]}" /usr/bin/docker pull --quiet "$PIPEGEN_IMAGE" > /dev/null']), { PIPEGEN_IMAGE: image }, `tool-pull-${sha16(artifact)}`));
    env.PIPEGEN_IMAGE = image;
    const docker = ['/usr/bin/docker', 'run', '--rm', '--pull=never'];
    // DAST steps (and only those) share the runner's network, because their target is the app started on it (ruling R-D); they run as their image user in a fresh, world-writable work folder
    const dast = tool.categories.some((c) => DAST_CATEGORIES.has(c));
    if ((pol.network === 'host' || pol.asImageUser === true) && !(dast && inWork)) {
      return refuse(`${show(tool.id)} asks for the host network or to run as its image user, which only a DAST step that mounts a fresh work folder (and no repo folder) may do.`);
    }
    if (pol.asImageUser === true) prep.push('chmod 0777 "$work"');
    else docker.push('--user', '"$(id -u):$(id -g)"');
    docker.push('--security-opt', 'no-new-privileges', '--cap-drop', 'ALL');
    if (pol.network === 'none') docker.push('--network', 'none');
    if (pol.network === 'host') docker.push('--network', 'host');
    const at = (mount as NonNullable<typeof mount>).at;
    if (inWork) {
      vars.push(`work="$RUNNER_TEMP/pipegen-work/${artifact}"`);
      prep.unshift('mkdir -p "$RUNNER_TEMP/pipegen-work"', 'mkdir "$work"');
      docker.push('-v', `"$work:${at}"`);
    } else docker.push('-v', `"$PWD:${at}"`);
    if (mount?.workdir === true) docker.push('-w', at);
    if (config !== null && !inWork) docker.push('-v', '"$cfg:/pipegen-cfg:ro"');
    if (archive !== undefined) {
      // the verified rules folder (or its chosen sub-folder), read-only, at the path the reviewed command names
      const sub = built.sub === undefined ? '' : `/${built.sub.slice(1, -1)}`;
      if (built.sub !== undefined) prep.push(`if [ -L "$rules"/${built.sub} ] || [ ! -d "$rules"/${built.sub} ]; then pg_fail "the rules folder is missing or a link"; fi`);
      docker.push('-v', `"$rules${sub}:${archive.dir}:ro"`);
      // tuning (6d): more rule folders of the same verified archive, each read-only at its own path (names are reviewed constants)
      for (const x of tuned.extraRules) {
        prep.push(`if [ -L "$rules"/${q(x)} ] || [ ! -d "$rules"/${q(x)} ]; then pg_fail "the rules folder is missing or a link"; fi`);
        docker.push('-v', `"$rules/${x}:${EXTRA_RULES_AT}/${x}:ro"`);
      }
    }
    for (const n of secrets) docker.push('-e', n);
    docker.push('"$PIPEGEN_IMAGE"', q(exe));
    prefix = docker.join(' ');
  } else if (kind === 'npm') {
    const bin = pol.npmBin;
    if (bin === undefined || !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(bin) || bin.includes('..')) return refuse(`${show(tool.id)} has no reviewed bin file, so pipegen won't run it.`);
    if (!isNpmName(install.package)) return refuse(`The npm package of ${show(tool.id)} is not a plain name.`);
    const pins = npmPins(tool, install);
    const setup = hooks.setupNode(service?.runtimeVersion);
    nodeMajor = setup.with?.['node-version'];
    if (nodeMajor === undefined || !/^\d{1,3}$/.test(nodeMajor)) return refuse('The Node setup step has no plain node-version.');
    steps.push({ ...setup, id: `pipegen-setup-node-${nodeMajor}` });
    pathValue = `$nodebin:${FIXED_PATH}`;
    if (checker) {
      vars.push(`npmdir="$RUNNER_TEMP/pipegen-npm/${artifact}"`);
      // install from the closure, check and run in ONE step: no step can run between the install and the check (review-6b-r2 C2)
      const inst = checkerInstall(tool, pins, options);
      installLines.push(...inst.lines);
      Object.assign(env, inst.env);
      env.PIPEGEN_NPM_EXPECT = JSON.stringify(pins);
      // variables for the tool that name a helper inside the install folder (never one the repo could supply)
      for (const [name, rel] of Object.entries(pol.closureEnv ?? {})) {
        if (!NAME_RE.test(name) || !/^node_modules\/[A-Za-z0-9_.@-]+(?:\/[A-Za-z0-9_.@-]+)*$/.test(rel) || rel.includes('..')) return refuse(`The closure variable ${show(name)} of ${show(tool.id)} is not a plain path inside the install folder.`);
        closureVars.push(`${name}="$npmdir/${rel}"`);
        passed.push(name);
      }
      // the pinned packages are checked, then the tree is made read-only, in the same step that starts the tool.
      // The `chmod -R a-w` is a SPEED BUMP, not a guard: a later step of the same user can `chmod -R u+w` and rewrite the tree
      // (review-6b-r2 C3). What guards the install is the one-step install-check-run and the job order rule (checkJobOrder).
      afterAllow.push(
        `js=${q(NPM_VERIFY_JS)}`,
        '( cd -- "$npmdir" && "${pg_env[@]}" "PIPEGEN_NPM_EXPECT=$PIPEGEN_NPM_EXPECT" "$nodebin/node" -e "$js" )',
        'chmod -R a-w "$npmdir"',
      );
      prefix = `"$nodebin/node" "$npmdir/node_modules/${install.package}/${bin}"`;
    } else {
      steps.push(...repoInstall(pins, artifact, nodeMajor, spec.workingDir));
      prefix = `"$nodebin/node" "$PWD/node_modules/${install.package}/${bin}"`;
    }
  } else {
    const parts = pipSteps(tool, install, artifact, hooks, options.pipClosures ?? PIP_CLOSURES);
    steps.push(...parts);
    vars.push(`venv="$RUNNER_TEMP/pipegen-venv/${artifact}"`);
    prefix = `"$venv/bin/${exe}"`;
    pathValue = `$venv/bin:${FIXED_PATH}`;
  }

  if (archive !== undefined) {
    steps.push(rulesStep(tool, archive, artifact, tplEnv, options.gitBase ?? GIT_BASE));
    vars.push(`rules="$RUNNER_TEMP/pipegen-rules/${artifact}"`);
  }
  // a repo path (hadolint's Dockerfile, kube-linter's folder) must exist, not be a link and stay inside the repository
  const pathChecks = built.paths.flatMap((v) => [
    `if [ -L ${v} ] || [ ! -e ${v} ]; then pg_fail "the path ${'$'}{${v.slice(2, -1)}} is missing or a link"; fi`,
    `case "$(/usr/bin/realpath -e -- ${v})" in "$(pwd -P)"|"$(pwd -P)"/*) ;; *) pg_fail "the path leaves the repository" ;; esac`,
  ]);

  // the pinned config goes in a file the tool is told about (ruling S4)
  const cfgLines = config === null && tunedCfg === null ? [] : checker || inWork
    ? [`printf '%s' "$PIPEGEN_CONFIG" > "${cfgBase}/${(config as PinnedConfig).fileName}"`]
    : ['mkdir -p "$RUNNER_TEMP/pipegen-cfg"', `cfg="$RUNNER_TEMP/pipegen-cfg/${artifact}"`, 'mkdir "$cfg"',
      ...(config === null ? [] : [`printf '%s' "$PIPEGEN_CONFIG" > "$cfg/${config.fileName}"`]),
      ...(tunedCfg === null ? [] : [`printf '%s' "$PIPEGEN_TUNED_CONFIG" > "$cfg/${tunedCfg.fileName}"`])];
  // the tool is told where its generated config is by the one variable the policy named (set inside env -i, like the other constants)
  const dynamicEnv = tunedCfg === null ? [] : [`${tunedCfg.envName}=$cfg/${tunedCfg.fileName}`];
  // NOTE (6d fix round 2): this edits `.semgrepignore` files in the checkout, so later steps of the same job see that (tracked ones deleted,
  // an untracked one added). No other tool reads them; Plan G should still place semgrep where no later workspace reader of the job cares.
  // the tool's own scope file replaces the repo's (semgrep: `.semgrepignore`, nested ones included): every file of that name under the
  // step folder is deleted (a link is removed, never followed), then pipegen's own is written. Marker comments let the live test run it.
  const scope = pol.scopeIgnore;
  if (scope !== undefined && (!/^\.[a-z][a-z0-9]{0,30}$/.test(scope.file) || !scope.lines.every((l) => /^[a-z_][a-z0-9_]{0,30}$/.test(l)))) return refuse(`The scope file of ${show(tool.id)} is not a plain name with plain lines.`);
  const scopeLines = scope === undefined ? [] : [
    '# pipegen scope: begin',
    // a folder of that name at the scan root can not be replaced by a file: say so plainly (fails closed; the PR author can only turn the gate red)
    `if [ -d ${scope.file} ] && [ ! -L ${scope.file} ]; then pg_fail "the repository has a folder named ${scope.file} at the scan root, so pipegen can not write its own scope file there"; fi`,
    `"\${sys[@]}" find . -name ${scope.file} \\( -type f -o -type l \\) -delete`,
    `printf '%s\\n' ${scope.lines.join(' ')} > ${scope.file}`,
    '# pipegen scope: end',
  ];
  // C1c: a secrets scan runs on the stage folder its stage step filled (gate/src/stage.ts), never on the checkout: the run checks the folder
  // and its manifest (no link), cds into the staged files (the tool's ignore-file lookup and its path allowlists see only neutral names),
  // refuses an ignore file there (a belt: the stage step never writes one) and writes its report into a fresh work folder outside them
  const staged = pol.staged;
  if (staged !== undefined) {
    if (spec.workingDir !== undefined) return refuse(`${show(tool.id)} scans the whole repository through its stage folder, so it can not run in a service folder.`);
    if (kind !== 'github-release' || out === null) return refuse(`${show(tool.id)} scans a stage folder, which only a release binary that writes a result file can.`);
    if (!staged.ignoreFiles.every((n) => /^\.[a-z][a-z0-9]{0,30}$/.test(n))) return refuse(`The ignore files of ${show(tool.id)} are not plain names.`);
    const at = built.main.findIndex((w, i) => i > 0 && built.main[i - 1] === '--report-path' && w === q(out));
    if (at < 0 || built.main.filter((w) => w === '--report-path').length !== 1) return refuse(`${show(tool.id)} scans a stage folder, so its command must name its result once, as --report-path ${show(out)}.`);
    built.main[at] = '"$out"';
  }
  const stageLines = staged === undefined ? [] : [
    `stage="$RUNNER_TEMP/pipegen-stage/${artifact}"`,
    'for d in "$stage" "$stage/files"; do',
    '  if [ -L "$d" ] || [ ! -d "$d" ]; then pg_fail "the stage folder $d is missing or a link: the stage step of this result must run before the scan"; fi',
    'done',
    'if [ -L "$stage/manifest.json" ] || [ ! -f "$stage/manifest.json" ]; then pg_fail "the stage manifest is missing or a link: the stage step of this result did not finish"; fi',
    'cd -- "$stage/files"',
    ...staged.ignoreFiles.map((n) => `if [ -e ${n} ] || [ -L ${n} ]; then pg_fail "the stage folder holds a file named ${n}, which the scanner would read as an ignore file"; fi`),
    `work="$RUNNER_TEMP/pipegen-work/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-work"',
    'mkdir "$work"',
  ];
  // what the tuning did, in plain words, in comment lines (describeTuning): one line of text each, nothing but printable ASCII
  const tuneComments = tuned.lines.map((l) => `# tuning: ${l.replace(/[^\x20-\x7e]/g, '?')}`);
  // the result path must be free before the tool runs and a regular file after it, also where it lands (ruling S7)
  const outDir = `$RUNNER_TEMP/pipegen-raw/${artifact}`;
  const preCheck = out === null ? [] : [
    inWork || staged !== undefined ? `out="$work/${out}"` : `out=${q(out)}`,
    inWork || staged !== undefined ? 'outdir="$work"' : 'outdir=.',
    'if [ -e "$out" ] || [ -L "$out" ]; then pg_fail "the result file $out exists before the tool ran, so pipegen will not use it"; fi',
    '[ -d "$outdir" ] && [ ! -L "$outdir" ] || pg_fail "the folder for the result is not a real folder"',
  ];
  // ruling B2: the exit codes that mean a scan that worked (0, and the findings codes of the policy); anything else is a tool error
  const okCodes = [0, ...(pol.findingsExit ?? [])];
  if (!okCodes.every((c) => Number.isInteger(c) && c >= 0 && c <= 125)) return refuse(`The findings exit codes of ${show(tool.id)} are not small whole numbers.`);
  const postCheck = out === null ? [] : [
    `case "$rc" in ${okCodes.join('|')}) ;; *)`,
    // the tool failed: its result is not trusted, so it is deleted (it may be half written, or hold anything), and the step fails with the tool's own code
    '  rm -rf -- "$out"',
    '  echo "pipegen: the tool exited with $rc, so its result is not used" >&2',
    '  exit "$rc" ;;',
    'esac',
    // nuclei writes no SARIF file when nothing matched (exit 0, measured, C1a review). After a clean exit, and only when there is no file at all
    // (never over one the tool wrote), pipegen writes a marked empty result: the gate reads it as "nothing reported", never as a nuclei run.
    ...(tool.id === 'nuclei' ? [`if [ "$rc" = 0 ] && [ ! -e "$out" ] && [ ! -L "$out" ]; then printf '%s\\n' '${NUCLEI_EMPTY_SARIF}' > "$out"; fi`] : []),
    'if [ -f "$out" ] && [ ! -L "$out" ]; then',
    '  mkdir -p "$RUNNER_TEMP/pipegen-raw"',
    `  mkdir "${outDir}"`,
    `  dest="${outDir}/${out}"`,
    '  mv -- "$out" "$dest"',
    '  if [ -f "$dest" ] && [ ! -L "$dest" ]; then rc=0; else rm -f -- "$dest"; rc=1; fi',
    // a speed bump, not a guard (review-6b-r2 C3): a later step of the same user can chmod it back
    `  chmod -R a-w "${outDir}"`,
    'else',
    '  echo "pipegen: the tool left no regular result file at $out" >&2',
    '  rm -rf -- "$out"',
    '  rc=1',
    'fi',
  ];
  // D9 (ruling B5): a tool that runs the service's tests (c8) gets the test command from the fixed table only, after `--`: never repo text,
  // never words of the entry (the loader refuses both). The executable is the Node setup step's own (`"$nodebin/npm"`), like the project scripts,
  // and the run gets their constant CI=true.
  const constants: string[] = [];
  if (pol.testCommand === true) {
    if (kind !== 'npm' || pol.runsRepoCode !== true || checker) return refuse(`${show(tool.id)} asks for a test command, which only an npm tool that runs repo code can run.`);
    if (service === undefined) return refuse(`${show(tool.id)} runs the tests of one service, and this step names none.`);
    const pm = service.packageManager;
    const row = typeof pm === 'string' && Object.hasOwn(TEST_COMMANDS, pm) ? TEST_COMMANDS[pm] : undefined;
    if (row === undefined) {
      return refuse(`${show(tool.id)} runs the service's tests with a fixed command, which pipegen has for npm services only in this version; the service ${show(service.name)} uses ${show(pm ?? 'no recognised package manager')}, so its coverage is not measured.`);
    }
    if (!service.scripts.includes('test')) return refuse(`The service ${show(service.name)} has no test script, so ${show(tool.id)} has no tests to run (npm test would only fail).`);
    if (!EXE_RE.test(row.exe)) return refuse(`The test command of ${show(tool.id)} is not a plain executable name.`);
    built.main.push('--', `"$nodebin/${row.exe}"`, ...row.args.map(q));
    constants.push('CI=true');
  }
  const launch = (words: readonly string[]): string => `${LAUNCH_ENV} ${prefix}${words.length === 0 ? '' : ` ${words.join(' ')}`}`;
  const chain = [launch(built.main), ...built.then.map(launch)].join(' && ');
  const fl = pol.fileList;
  if (fl !== undefined && (built.then.length > 0 || out !== null || staged !== undefined)) return refuse(`${show(tool.id)} lints a file list, which only a single command without a result file can.`);
  let listLines: string[];
  try { listLines = fl === undefined ? [] : [`list="$RUNNER_TEMP/pipegen-files/${artifact}"`, 'mkdir -p "$RUNNER_TEMP/pipegen-files"', 'rm -f -- "$list"', ...fileListLines(fl.extensions, '"$list"')]; } catch { return refuse(`The file list of ${show(tool.id)} is not a list of plain extensions.`); }
  const runLines = fl === undefined ? [`${chain} || rc=$?`] : fileListRun(launch(built.main), '"$list"');
  const run = script([
    ...prologue(artifact, nodeMajor === undefined ? {} : { nodeMajor }), ...tuneComments, ...vars, ...installLines, ...cdLines(spec.workingDir), ...pathChecks, ...prep, ...cfgLines, ...scopeLines, ...stageLines, ...preCheck,
    ...closureVars, ...allowlist(pathValue, passed, constants, dynamicEnv), ...afterAllow, ...listLines, 'rc=0', ...runLines, ...postCheck, 'exit "$rc"',
  ]);
  // a tool that runs the repo's own code is marked, so the referee can apply its order rule (S6 c); the id is not `pipegen-…`, which a job's dedupe may drop
  // fail closed: the run is repo code unless the policy says it only reads (readsOnly), and never for an app-running category
  const appRunning = tool.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
  const runId = runsRepoCode(pol, appRunning) ? `repocode-${sha16(artifact)}` : checker ? `checker-run-${sha16(artifact)}` : `tool-run-${sha16(artifact)}`;
  steps.push(runStep(`pipegen: run ${exe}`, run, env, runId));
  return { steps, output: out === null ? null : { path: `\${{ runner.temp }}/pipegen-raw/${artifact}/${out}`, format: tool.step.output.format }, ...(built.fullHistory ? { fullHistory: true as const } : {}) };
}

// ---------- the commit-range secrets scan (C9) ----------

/** C9: the config of the range scan: pipegen's pinned betterleaks config (the canary rule included) with no global path allowlist. */
export const RANGE_PREFILTER = "prefilter = '''false'''\n\n";
/** C9 fix round 1: the date of the canary commits (2100-01-01), later than any real commit, so the date-ordered stream ends with them. */
const CANARY_DATE = '@4102444800 +0000';
/** The oldest git with `--remerge-diff` (2.36). */
const REMERGE_GIT = [2, 36] as const;

/**
 * The text Plan G prints in PIPEGEN.md about the commit-range scan (C9 and its fix round 1), so the residuals are said where people read them.
 */
export const RANGE_PIPEGEN_NOTE = [
  'pipegen also scans every commit a pull request pushes, not only its last one: a secret added in one commit and removed in a later one still blocks, because it was pushed and has leaked. Rotate it now.',
  'When a push rewrites the pull request (a force-push), the commits it replaced are scanned too, once, on that push. A commit replaced two or more pushes ago is no longer in the range: a secret pushed is leaked whatever later pushes do, so rotate it when pipegen first reports it.',
  'A merge from the default branch into the pull request brings that branch\'s newer commits into the range: a secret there blocks the pull request too. A merge commit is scanned for what its own resolution added.',
  'A merge commit with three or more parents (an octopus merge) can not be shown with only its own changes, so a pull request that holds one is not scanned and blocks: merge one branch at a time.',
  'On a push to the default branch the commit range is informational. A push that rewrote the default branch (a force-push) is scanned from where its old and new heads meet; when the old head is gone, it is not scanned (a warning).',
  'Commit messages are not scanned for secrets.',
].join('\n\n');

/**
 * The commit-range secrets scan (C9, Plan C final review Important 2; fix round 1, review-C9.md I1 to I3): the reviewed betterleaks entry's
 * release install, then ONE checker step that scans the pull request's commits in `git` mode, as one ordered stream. Every word is a reviewed
 * constant; the only values from outside are this event's base, head and before commits, which come in the step env (the event-switched forms
 * RANGE_STEP_ENV) and must each be 40 hex digits.
 *
 * Measured with the pinned betterleaks 1.9.0 (the C9 report and review have the logs):
 * - git mode applies the config's global path allowlist (node_modules/, package-lock.json, …), so the config is the entry's own with
 *   `prefilter = '''false'''` put first (a prefilter after [extend] is read as extend.prefilter and changes nothing). The rules' own narrow
 *   path conditions (betterleaks' isCodeFile discard of an unquoted password in code, the bitbake SRC= lines, the octokit README) still apply
 *   here, on the real paths, where the HEAD scan's neutral staged names never meet them: the range can report a little less than the HEAD scan
 *   of the same file, never more hidden than an unstaged scan;
 * - betterleaks reads `.betterleaksignore` / `.gitleaksignore` from the folder it scans whatever --gitleaks-ignore-path says, so it runs from
 *   an empty folder whose `.git` file names the checkout's git folder;
 * - single mode (`--git-workers 0`) hands --log-opts to ONE `git log -p -U0`: `--reverse` prints the oldest commit first, `--text` makes every
 *   file text to the diff (archives, NUL bytes, the repository's `-diff` and `binary` attributes, type changes are all read), and
 *   `--remerge-diff` shows each merge commit as what its own resolution added to the automatic merge of its parents (a conflict resolution, a
 *   file staged while resolving), so merges are in the range. The parallel mode of the first round read chunks the step could not prove
 *   (review I1), and is gone with its count check and its workarounds.
 * Completeness (I1): two canary commits on the head, each its parent's tree plus one canary file, dated after every real commit, so the
 * reversed stream ends with them (the step checks the stream order with `git rev-list --reverse` of the same revisions and fails when they are
 * not the last two). The scanner reports a finding when it reads it, so the tip canary is found only when the stream was read to its end: a
 * stream cut short anywhere (a parse error, a killed git) has no tip canary, and the scrub calls that a tool error.
 * The dropped commits (I2): on a synchronize, `before` (the previous head) is a revision of the stream too (`^base <tip> <before>`): the
 * commits a force-push replaced. A `before` not in the checkout is fetched by sha; one that can not be fetched fails the step. Residual: a
 * commit replaced two or more pushes ago is no longer in any range (RANGE_PIPEGEN_NOTE).
 * Fix round 2 (review-C9-r1.md): on a push (the event comes in its own exact form, RANGE_EVENT_REF), an old head that is not an ancestor of the
 * new one (a force-push) moves the range's base to where the two meet (`git merge-base`, the facts say `forced`); with the old head gone from
 * the checkout there is no such point, and the step skips (`no-merge-base`, a warning in the gate). A range holding an octopus merge (three or
 * more parents, whose own changes --remerge-diff can not show) fails the step. Every git command runs with GIT_NO_REPLACE_OBJECTS=1.
 * Not scanned: commit messages and author fields (betterleaks reads the patches only; a known limit, carried to Plan P).
 * No range on this event (an all-zero base or head: a push that made the branch, workflow_dispatch, schedule): the step writes the facts
 * `{ skipped: 'no-range' }` and exits 0; the gate reads that as not applicable on those events only, and blocks on a pull request event.
 * Any other failure fails the step and leaves no raw result (the scrub then reports a tool error). A merge from the default branch brings
 * that branch's newer commits into the range: a secret there blocks too (false blocks only, fail closed).
 */
export function renderRangeScan(tool: ReviewedTool): RenderResult {
  const pol = own(ARGV_POLICIES, tool.id);
  if (tool.id !== RANGE_TOOL || pol === undefined || pol.method !== 'github-release') return refuse(`The commit-range scan runs the reviewed ${RANGE_TOOL} entry only, not ${show(tool.id)}.`);
  const install = checkInstall(tool, pol);
  const config = configOf(tool, pol);
  if (config === null || !config.content.startsWith('[extend]\n')) return refuse(`The pinned config of ${show(tool.id)} does not start with its [extend] table, so the range scan can not put its prefilter first.`);
  const out = tool.step.output.path;
  if (!PLAIN_OUT_RE.test(out) || tool.step.output.format !== 'sarif') return refuse(`${show(tool.id)} does not write a SARIF file with a plain name.`);
  const artifact = SECRETS_RANGE_ARTIFACT;
  const exe = pol.exe;
  const outDir = `$RUNNER_TEMP/pipegen-raw/${artifact}`;
  const zero = '0'.repeat(40);
  const [c1, c2] = RANGE_CANARY_FILES;
  const notCommits = 'pg_fail "the commit range is not given as commit shas, so it is not scanned"';
  const run = script([
    ...prologue(artifact),
    `bin="$RUNNER_TEMP/pipegen-bin/${artifact}"`,
    `work="$RUNNER_TEMP/pipegen-work/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-work"',
    'mkdir "$work"',
    // the range: this event's base, head and (on a synchronize) before, each a commit sha (the hex test also stops `HEAD~000…`, which git resolves)
    'base="$PIPEGEN_RANGE_BASE"',
    'head="$PIPEGEN_RANGE_HEAD"',
    'before="$PIPEGEN_RANGE_BEFORE"',
    'for c in "$base" "$head" "$before"; do',
    `  case "$c" in *[!0-9a-f]*|"") ${notCommits} ;; esac`,
    `  [ "\${#c}" -eq 40 ] || ${notCommits}`,
    'done',
    // no range on this event: a note, and facts that say so (the gate blocks on a pull request event, and notes it on the others)
    // a skip: a note, and facts that say why (the gate blocks on a pull request event, and notes or warns on the others)
    'skip() {',
    '  echo "pipegen: $2"',
    '  mkdir -p "$RUNNER_TEMP/pipegen-raw"',
    `  mkdir "${outDir}"`,
    `  printf '{"pipegenRange":1,"skipped":"%s"}\\n' "$1" > "${outDir}/${RANGE_FACTS_FILE}"`,
    `  chmod -R a-w "${outDir}"`,
    '  exit 0',
    '}',
    'event="$PIPEGEN_RANGE_EVENT"',
    'case "$event" in pull_request|pull_request_review|merge_group|push|workflow_dispatch|schedule|workflow_call) ;; *) pg_fail "the event name is not one the range scan knows, so it is not scanned" ;; esac',
    `if [ "$base" = ${zero} ] || [ "$head" = ${zero} ]; then skip no-range "this event has no commit range (a push that made the branch, workflow_dispatch or schedule), so no commit range is scanned"; fi`,
    'git=(',
    '  "${sys[@]}"',
    '  GIT_CONFIG_NOSYSTEM=1',
    '  GIT_CONFIG_GLOBAL=/dev/null',
    '  GIT_TERMINAL_PROMPT=0',
    '  GIT_ALLOW_PROTOCOL=https',
    // fix round 2 (m5): the step's own git reads the same objects as the scanner's (betterleaks sets it for its git): no refs/replace
    '  GIT_NO_REPLACE_OBJECTS=1',
    '  GIT_AUTHOR_NAME=pipegen',
    '  GIT_AUTHOR_EMAIL=pipegen@invalid',
    `  'GIT_AUTHOR_DATE=${CANARY_DATE}'`,
    '  GIT_COMMITTER_NAME=pipegen',
    '  GIT_COMMITTER_EMAIL=pipegen@invalid',
    `  'GIT_COMMITTER_DATE=${CANARY_DATE}'`,
    '  /usr/bin/git',
    ')',
    // --remerge-diff needs git 2.36 or later
    'gv="$("${git[@]}" version)"',
    'case "$gv" in "git version "[0-9]*.[0-9]*) ;; *) pg_fail "the version of git could not be read, so merge commits can not be scanned" ;; esac',
    'gv="${gv#git version }"',
    'gmaj="${gv%%.*}"',
    'gmin="${gv#*.}"',
    'gmin="${gmin%%[!0-9]*}"',
    'case "$gmaj$gmin" in *[!0-9]*|"") pg_fail "the version of git could not be read, so merge commits can not be scanned" ;; esac',
    `if [ "$gmaj" -lt ${REMERGE_GIT[0]} ] || { [ "$gmaj" -eq ${REMERGE_GIT[0]} ] && [ "$gmin" -lt ${REMERGE_GIT[1]} ]; }; then pg_fail "git $gv can not show what a merge commit added (--remerge-diff needs git ${REMERGE_GIT.join('.')}), so the commit range is not scanned"; fi`,
    '"${git[@]}" cat-file -e "$head^{commit}" 2> /dev/null || pg_fail "the commit $head is not in the checkout: the secrets job checks out the whole history (fetch-depth: 0)"',
    // fix round 2 (m2): a push that rewrote the branch (its old head is not an ancestor of the new one): scan from where they meet; when the
    // old head is gone from the checkout, there is no such point, and the push is not scanned (on a push the range is informational)
    'forced=false',
    'if [ "$event" = push ] && ! "${git[@]}" merge-base --is-ancestor "$base" "$head" 2> /dev/null; then',
    '  mb=""',
    '  if "${git[@]}" cat-file -e "$base^{commit}" 2> /dev/null; then mb="$("${git[@]}" merge-base "$base" "$head" 2> /dev/null || true)"; fi',
    '  case "$mb" in *[!0-9a-f]*|"") skip no-merge-base "this push rewrote the history of the branch and its old head $base is not in the checkout, so its commit range is not scanned" ;; esac',
    '  [ "${#mb}" -eq 40 ] || skip no-merge-base "this push rewrote the history of the branch and its old head $base is not in the checkout, so its commit range is not scanned"',
    '  echo "pipegen: this push rewrote the history of the branch (its old head $base is not an ancestor of $head); the range is scanned from where they meet, $mb"',
    '  base="$mb"',
    '  forced=true',
    'fi',
    '"${git[@]}" cat-file -e "$base^{commit}" 2> /dev/null || pg_fail "the commit $base is not in the checkout: the secrets job checks out the whole history (fetch-depth: 0)"',
    // the commits a force-push dropped: fetched by sha when the checkout does not hold them (a pushed commit stays fetchable)
    'revs=()',
    `if [ "$before" != ${zero} ]; then`,
    '  if ! "${git[@]}" cat-file -e "$before^{commit}" 2> /dev/null; then',
    '    "${git[@]}" fetch --quiet --no-tags --no-recurse-submodules origin "$before" > /dev/null 2>&1 || true',
    '    "${git[@]}" cat-file -e "$before^{commit}" 2> /dev/null || pg_fail "the head before this push ($before) could not be fetched, so the commits the push dropped are not scanned"',
    '  fi',
    '  revs+=("$before")',
    'fi',
    'gitdir="$("${git[@]}" rev-parse --absolute-git-dir)"',
    'if [ -L "$gitdir" ] || [ ! -d "$gitdir" ]; then pg_fail "the git folder of the checkout is not a real folder"; fi',
    // two canary commits on the head, each its parent's tree plus one canary file (local objects only, dated after every real commit)
    'canary() { printf \'pipegen-canary-%s\' "$("${sys[@]}" od -An -N16 -tx1 /dev/urandom | "${sys[@]}" tr -d \' \\n\')"; }',
    'parent="$head"',
    'canaries=()',
    `for f in ${c1} ${c2}; do`,
    '  line="$(canary)"',
    '  case "$line" in pipegen-canary-*[!0-9a-f]*) pg_fail "a canary could not be made" ;; esac',
    '  [ "${#line}" -eq 47 ] || pg_fail "a canary could not be made"',
    '  blob="$("${git[@]}" hash-object -w --stdin <<< "$line")"',
    '  "${git[@]}" ls-tree -z "$parent" > "$work/tree.bin"',
    '  while IFS= read -r -d \'\' e; do',
    '    case "$e" in *$\'\\t\'"$f") ;; *) printf \'%s\\0\' "$e" ;; esac',
    '  done < "$work/tree.bin" > "$work/tree2.bin"',
    '  printf \'100644 blob %s\\t%s\\0\' "$blob" "$f" >> "$work/tree2.bin"',
    '  tree="$("${git[@]}" mktree -z < "$work/tree2.bin")"',
    '  parent="$("${git[@]}" commit-tree "$tree" -p "$parent" -m \'pipegen: commit-range canary\' < /dev/null)"',
    `  case "$parent" in *[!0-9a-f]*|"") pg_fail "a canary commit could not be made" ;; esac`,
    '  [ "${#parent}" -eq 40 ] || pg_fail "a canary commit could not be made"',
    '  canaries+=("$parent")',
    'done',
    'last="$parent"',
    // the stream: everything reachable from the tip canary (and before), not from the base; the two canaries must be its last commits
    '"${git[@]}" rev-list --reverse "^$base" "$last" "${revs[@]}" > "$work/order.txt"',
    'want="$("${sys[@]}" wc -l < "$work/order.txt")"',
    'case "$want" in *[!0-9]*|"") pg_fail "the commits of the range could not be counted" ;; esac',
    '[ "$want" -ge 2 ] || pg_fail "the commits of the range could not be counted"',
    'tail2="$("${sys[@]}" tail -n 2 -- "$work/order.txt" | "${sys[@]}" tr \'\\n\' \' \')"',
    '[ "$tail2" = "${canaries[0]} ${canaries[1]} " ] || pg_fail "a commit of the range is dated after the canary commits, so the canary is not the last commit the scanner reads and the stream can not be proven read to its end"',
    'own=$((want - 2))',
    // fix round 2 (m3): --remerge-diff shows nothing of a merge with three or more parents, so a range that holds one is not scanned
    '"${git[@]}" rev-list --min-parents=3 "^$base" "$last" "${revs[@]}" > "$work/octopus.txt"',
    'if [ -s "$work/octopus.txt" ]; then pg_fail "the commit range holds an octopus merge (commit $("${sys[@]}" head -n 1 -- "$work/octopus.txt"), three or more parents), whose own changes can not be shown, so the range is not scanned: merge one branch at a time"; fi',
    // the scanner runs from an empty folder whose .git file names the checkout's git folder (no ignore file of the checkout is read)
    'src="$work/src"',
    'mkdir "$src"',
    'printf \'gitdir: %s\\n\' "$gitdir" > "$src/.git"',
    `printf '%s' "$PIPEGEN_CONFIG" > "$work/${config.fileName}"`,
    `out="$work/${out}"`,
    'logopts="--reverse --remerge-diff --text ^$base $last${revs[0]:+ ${revs[0]}}"',
    'cd -- "$src"',
    ...allowlist(FIXED_PATH, []),
    'rc=0',
    `${LAUNCH_ENV} ${releaseLauncher(exe)} git --no-banner --no-color --log-level info --ignore-gitleaks-allow --redact --report-format sarif --report-path "$out" --exit-code 10 --max-archive-depth 0 --git-workers 0 ${config.flag} "$work/${config.fileName}" --log-opts "$logopts" . || rc=$?`,
    'case "$rc" in 0|10) ;; *)',
    '  rm -rf -- "$out"',
    '  echo "pipegen: the tool exited with $rc, so its result is not used" >&2',
    '  exit "$rc" ;;',
    'esac',
    'if [ -f "$out" ] && [ ! -L "$out" ]; then',
    '  mkdir -p "$RUNNER_TEMP/pipegen-raw"',
    `  mkdir "${outDir}"`,
    '  bjson=null',
    `  [ "$before" = ${zero} ] || bjson="\\"$before\\""`,
    `  printf '{"pipegenRange":1,"base":"%s","head":"%s","before":%s,"forced":%s,"commits":%s,"canaries":[{"commit":"%s","path":"${c1}"},{"commit":"%s","path":"${c2}"}]}\\n' "$base" "$head" "$bjson" "$forced" "$own" "\${canaries[0]}" "\${canaries[1]}" > "${outDir}/${RANGE_FACTS_FILE}"`,
    `  mv -- "$out" "${outDir}/${out}"`,
    `  chmod -R a-w "${outDir}"`,
    'else',
    '  pg_fail "the tool left no regular result file"',
    'fi',
  ]);
  const env: Record<string, string> = { ...RANGE_STEP_ENV, PIPEGEN_CONFIG: RANGE_PREFILTER + config.content };
  return {
    steps: [releaseInstall(tool, install, exe, artifact), runStep('pipegen: scan the pull request\'s commits for secrets', run, env, rangeScanStepId)],
    output: { path: `\${{ runner.temp }}/pipegen-raw/${artifact}/${out}`, format: 'sarif' },
    fullHistory: true,
  };
}

/** The marked empty result of a nuclei run that wrote no file (gate/src/sarif.ts SYNTHESIZED_NUCLEI is the same text; a test compares). */
export const NUCLEI_EMPTY_SARIF = '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"pipegen-empty-nuclei"}},"results":[],"properties":{"pipegenSynthesized":"nuclei-no-file"}}]}';

// ---------- github-release (ruling S27) ----------

const ARCHIVE_SUFFIXES = ['.tar.xz', '.tar.bz2', '.tar.zst', '.tar', '.gz', '.xz', '.bz2', '.zst', '.7z', '.rar', '.deb', '.rpm', '.pkg', '.msi', '.exe', '.dmg', '.apk', '.whl', '.jar'];

function releaseInstall(tool: ReviewedTool, install: InstallSpec, exe: string, artifact: string): RenderedStep {
  const repo = tool.candidate.repo;
  const hash = tool.candidate.pin.checksum;
  if (!isGitHubRepo(repo)) return refuse(`The repo of ${show(tool.id)} is not a GitHub owner/name.`);
  if (!TAG_RE.test(install.version)) return refuse(`The version of ${show(tool.id)} is not a plain release tag.`);
  if (!ASSET_RE.test(install.package)) return refuse(`The release asset of ${show(tool.id)} is not a plain file name.`);
  if (hash === undefined || !SHA256_RE.test(hash)) return refuse(`The pinned checksum of ${show(tool.id)} is not a sha256.`);
  const asset = install.package;
  const url = `https://github.com/${repo}/releases/download/${install.version}/${asset}`;
  const archive = asset.endsWith('.tar.gz') || asset.endsWith('.tgz') ? 'tar' : asset.endsWith('.zip') ? 'zip' : null;
  if (archive === null && ARCHIVE_SUFFIXES.some((s) => asset.endsWith(s))) return refuse(`The release asset ${show(asset)} is an archive type pipegen does not unpack.`);
  const lines = [
    ...prologue(artifact),
    `bin="$RUNNER_TEMP/pipegen-bin/${artifact}"`,
    `dl="$RUNNER_TEMP/pipegen-dl/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-bin" "$RUNNER_TEMP/pipegen-dl"',
    'mkdir "$bin" "$dl"',
    "\"${sys[@]}\" curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --max-redirs 5 --retry 3 --output \"$dl/asset\" \"$PIPEGEN_DL_URL\"",
    'cd "$dl"',
    "printf '%s  asset\\n' \"$PIPEGEN_DL_SHA256\" | \"${sys[@]}\" sha256sum --check --strict -",
    ...(archive === null ? [`mv -- "$dl/asset" "$bin/${exe}"`] : [
      'mkdir "$bin/pkg"',
      archive === 'tar' ? '"${sys[@]}" tar -xzf asset -C "$bin/pkg" --no-same-owner' : '"${sys[@]}" unzip -q asset -d "$bin/pkg"',
      `n="$("\${sys[@]}" find "$bin/pkg" -name ${q(exe)} -type f | wc -l)"`,
      `o="$("\${sys[@]}" find "$bin/pkg" -name ${q(exe)} ! -type f | wc -l)"`,
      `if [ "$n" -ne 1 ] || [ "$o" -ne 0 ]; then pg_fail "the archive must hold exactly one regular file named ${exe}"; fi`,
      `found="$("\${sys[@]}" find "$bin/pkg" -name ${q(exe)} -type f)"`,
      `mv -- "$found" "$bin/${exe}"`,
    ]),
    `if [ ! -f "$bin/${exe}" ] || [ -L "$bin/${exe}" ]; then pg_fail "the tool is not a regular file"; fi`,
    `chmod 0755 "$bin/${exe}"`,
  ];
  return runStep(`pipegen: install ${exe}`, script(lines), { PIPEGEN_DL_URL: url, PIPEGEN_DL_SHA256: hash }, `tool-install-${sha16(artifact)}`);
}

// ---------- docker (ruling S26) ----------

/** The image to run: the entry's own image name at its pinned digest. */
function imageOf(tool: ReviewedTool, install: InstallSpec): string {
  const digest = tool.candidate.pin.digest;
  if (parseImageRef(install.package) === null) return refuse(`The image of ${show(tool.id)} is not a plain image name.`);
  if (digest === undefined || !DIGEST_RE.test(digest)) return refuse(`The pinned digest of ${show(tool.id)} is not a sha256 digest.`);
  return `${install.package}@${digest}`;
}

// ---------- npm (DECISIONS #107, replaces ruling B5's npm half) ----------
//
// Two classes. A CHECKER (biome, eslint, oxlint, prettier, knip: it only reads code) is installed from pipegen's own
// closure lock into a fresh folder under runner temp, with empty npm configs and the registry on the command line, and
// run with node directly: the repo's lockfile, .npmrc and node_modules are never read, so a PR author can't change what
// the gate's checker is. A tool that RUNS REPO CODE (vitest, c8) needs the repo's own dependency tree; its result is only as
// trustworthy as the repo code it runs anyway. It gets a static check of the lockfile entries of the tool and its plugins
// BEFORE `npm ci`, the registry on the command line, a verification afterwards, and node directly (no npx). KNOWN LIMIT:
// for that class the transitive dependencies, and the repo's own .npmrc, stay repo-controlled.

const NPM_VERSION_RE = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,40})?$/;
const REGISTRY_URL = 'https://registry.npmjs.org/';
const MAX_LOCK_BYTES = 120 * 1024;

/** The registry tarball of a package version: the only `resolved` value a pin may have. */
const tarballOf = (name: string, version: string): string => `${REGISTRY_URL}${name}/-/${name.slice(name.indexOf('/') + 1)}-${version}.tgz`;

/** The checks that follow an install: each pinned package is a real folder (not a link) inside node_modules, at its version, with the registry entry npm wrote. Constant, so it can be quoted whole. */
const NPM_VERIFY_JS = [
  'const fs = require("fs"), path = require("path");',
  'const want = JSON.parse(process.env.PIPEGEN_NPM_EXPECT);',
  'let bad = 0;',
  'const fail = (m) => { console.error("pipegen: " + m); bad = 1; };',
  'let top = null;',
  'try { top = fs.lstatSync("node_modules"); } catch (e) { top = null; }',
  'if (!top || !top.isDirectory() || top.isSymbolicLink()) { fail("node_modules is not a real folder"); process.exit(1); }',
  'const root = fs.realpathSync("node_modules");',
  'let hidden = {};',
  'try { hidden = JSON.parse(fs.readFileSync("node_modules/.package-lock.json", "utf8")).packages || {}; } catch (e) { hidden = {}; }',
  'for (const w of want) {',
  '  const dir = path.join("node_modules", w.name);',
  '  let st = null;',
  '  try { st = fs.lstatSync(dir); } catch (e) { st = null; }',
  '  if (!st || !st.isDirectory() || st.isSymbolicLink()) { fail(w.name + " is not a real folder in node_modules"); continue; }',
  '  if (!fs.realpathSync(dir).startsWith(root + path.sep)) { fail(w.name + " is outside node_modules"); continue; }',
  '  let version = null;',
  '  try { version = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).version; } catch (e) { version = null; }',
  '  if (version !== w.version) fail(w.name + " is " + version + ", not the reviewed " + w.version);',
  '  const h = hidden["node_modules/" + w.name];',
  '  if (!h || h.integrity !== w.integrity || h.resolved !== w.resolved) fail(w.name + " was not installed from the reviewed registry tarball");',
  '}',
  'process.exit(bad);',
].join('\n');

/**
 * A plain `function name(...) {...}` as an anonymous function expression on one line, to embed in a step script (review-D6 m6). The name is
 * dropped whatever it is: a bundler renames a top-level function on a collision (esbuild: `pinOk2`), and the old fixed `function pinOk`
 * match then left `function 2(p, w)`, a syntax error in every npm precheck. Anything that is not a plain function (an arrow, a class, a
 * method, an async or generator function) is refused at load, never embedded half-rewritten. So is any text holding `//` or `/*` (D9 m4).
 */
export function functionSource(f: (...a: never[]) => unknown): string {
  const text = Function.prototype.toString.call(f);
  const re = /^function\s*[\w$]*\s*\(/;
  if (!re.test(text)) throw new Error('functionSource takes a plain function (function name(...) { ... }) only');
  // D9 m4: the text is folded onto one line, so a `//` comment would swallow the rest of the embedded script; no comment of either kind is embedded
  if (/\/[/*]/.test(text)) throw new Error('functionSource refuses a function whose text holds a comment (// or /*): it is folded onto one line');
  return text.replace(re, 'function(').replace(/\s*\n\s*/g, ' ');
}

/** The static check of a repo lockfile, run BEFORE `npm ci`: the tool and its plugins are plain registry packages at the reviewed version and integrity, and no shrinkwrap overrides the lockfile. */
const NPM_PRECHECK_JS = [
  'const fs = require("fs");',
  'let sw = null;',
  'try { sw = fs.lstatSync("npm-shrinkwrap.json"); } catch (e) { sw = null; }',
  'if (sw) { console.error("pipegen: npm-shrinkwrap.json takes precedence over package-lock.json; pipegen will not install with it"); process.exit(1); }',
  'const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));',
  'const want = JSON.parse(process.env.PIPEGEN_NPM_EXPECT);',
  'let bad = 0;',
  `const pinOk = ${functionSource(pinOk)};`,
  'for (const w of want) {',
  '  const p = (lock.packages || {})["node_modules/" + w.name];',
  '  if (!pinOk(p, w)) {',
  '    console.error("pipegen: " + w.name + " is not the reviewed " + w.version + " from the registry in package-lock.json (a link, an alias, another source or another hash)");',
  '    bad = 1;',
  '  }',
  '}',
  'process.exit(bad);',
].join('\n');

/** The tool and every plugin with the exact version, integrity and registry tarball they must have. */
function npmPins(tool: ReviewedTool, install: InstallSpec): (NpmPin & { resolved: string })[] {
  const cli = tool.step.cli as NonNullable<typeof tool.step.cli>;
  const all: { name: string; version: string; integrity: string | undefined }[] = [
    { name: install.package, version: install.version, integrity: tool.candidate.pin.checksum },
    ...(cli.plugins ?? []).map((p) => ({ name: p.package, version: p.version, integrity: p.checksum })),
  ];
  return all.map((p) => {
    if (!isNpmName(p.name) || !NPM_VERSION_RE.test(p.version) || p.integrity === undefined || !SRI_SHA512_RE.test(p.integrity)) {
      return refuse(`The npm package ${show(p.name)} of ${show(tool.id)} is not a plain name at an exact version with a sha512 integrity.`);
    }
    return { name: p.name, version: p.version, integrity: p.integrity, resolved: tarballOf(p.name, p.version) };
  });
}

/**
 * The lines that install a checker from pipegen's closure lock (nothing from the repo), and the step env they need. They
 * run at the top of the SAME step that verifies and starts the tool, so nothing can run between install and use.
 */
function checkerInstall(tool: ReviewedTool, pins: readonly (NpmPin & { resolved: string })[], options: RenderOptions): { lines: string[]; env: Record<string, string> } {
  let lock: string;
  try {
    const reader = options.npmClosures === undefined ? undefined : (id: string): string => {
      const text = options.npmClosures?.[id];
      if (text === undefined) throw new Error('no closure');
      return text;
    };
    lock = loadNpmClosure(tool.id, pins, reader);
  } catch (e) {
    return refuse(e instanceof NpmClosureError ? e.message : `the npm closure lock of ${show(tool.id)} could not be read`);
  }
  const compact = JSON.stringify(JSON.parse(lock));
  if (compact.length > MAX_LOCK_BYTES) return refuse(`The npm closure lock of ${show(tool.id)} is too large to carry in a workflow.`);
  const pkg = JSON.stringify({ name: 'pipegen-closure', version: '0.0.0', private: true, dependencies: closureRootDependencies(lock) });
  const lines = [
    'mkdir -p "$RUNNER_TEMP/pipegen-npm"',
    'mkdir "$npmdir"',
    'printf \'%s\' "$PIPEGEN_NPM_LOCK" > "$npmdir/package-lock.json"',
    'printf \'%s\' "$PIPEGEN_NPM_PACKAGE" > "$npmdir/package.json"',
    ': > "$npmdir/.npmrc"',
    ': > "$npmdir/user.npmrc"',
    ': > "$npmdir/global.npmrc"',
    ...allowlist(`$nodebin:${FIXED_PATH}`, []),
    `( cd -- "$npmdir" && "\${pg_env[@]}" "$nodebin/npm" ci --ignore-scripts --no-audit --no-fund --userconfig "$npmdir/user.npmrc" --globalconfig "$npmdir/global.npmrc" --workspaces=false --registry=${REGISTRY_URL} )`,
  ];
  return { lines, env: { PIPEGEN_NPM_LOCK: compact, PIPEGEN_NPM_PACKAGE: pkg } };
}

/** For a tool that runs repo code: the guarded `npm ci` of the repo (ids deduped per job and folder) and the verification step that needs its marker. */
function repoInstall(pins: readonly (NpmPin & { resolved: string })[], artifact: string, nodeMajor: string, workingDir: string | undefined): RenderedStep[] {
  const folder = (workingDir ?? '').split('/').filter((p) => p !== '' && p !== '.').join('/');
  const hash = sha16(folder === '' ? '.' : folder);
  const marker = `$RUNNER_TEMP/pipegen-npm-ci/${hash}`;
  const expect = { PIPEGEN_NPM_EXPECT: JSON.stringify(pins) };
  const common = [...prologue(artifact, { nodeMajor }), ...cdLines(workingDir), ...allowlist(`$nodebin:${FIXED_PATH}`, [])];
  const ci = runStep('pipegen: install the project dependencies (npm ci, no scripts)', script([
    ...common,
    `js=${q(NPM_PRECHECK_JS)}`,
    '"${pg_env[@]}" "PIPEGEN_NPM_EXPECT=$PIPEGEN_NPM_EXPECT" "$nodebin/node" -e "$js"',
    `"\${pg_env[@]}" "$nodebin/npm" ci --ignore-scripts --no-audit --no-fund --workspaces=false --registry=${REGISTRY_URL}`,
    'mkdir -p "$RUNNER_TEMP/pipegen-npm-ci"',
    `: > "${marker}"`,
  ]), expect, `pipegen-npm-ci-${hash}`);
  const verify = runStep('pipegen: check the installed tool against the lockfile', script([
    ...common,
    `[ -f "${marker}" ] && [ ! -L "${marker}" ] || pg_fail "the dependencies were not installed by pipegen's own npm ci step"`,
    `js=${q(NPM_VERIFY_JS)}`,
    '"${pg_env[@]}" "PIPEGEN_NPM_EXPECT=$PIPEGEN_NPM_EXPECT" "$nodebin/node" -e "$js"',
  ]), expect);
  return [ci, verify];
}

/**
 * The steps of a project script (ruling S10): the guarded repo `npm ci` (shared with the repo-code tools, same id and marker)
 * and the script itself, which is repo code (`repocode-…` id). `workingDir` is the already-checked service folder.
 */
export function projectScriptSteps(artifact: string, which: 'test' | 'lint', nodeMajor: string, workingDir: string | undefined): RenderedStep[] {
  const ci = repoInstall([], artifact, nodeMajor, workingDir)[0] as RenderedStep;
  const run = script([
    ...prologue(artifact, { nodeMajor }), ...cdLines(workingDir),
    // repo code, but not with the job's whole environment: the same env -i allowlist as the other repo-code tools (ruling S6 b), so
    // the OIDC request token, NODE_OPTIONS, NPM_CONFIG_* and the runner HOME never reach the repo's script. CI=true is set
    // here, as a constant (7a Part 0): many test runners change behaviour without it (watch mode, prompts, snapshots written)
    ...allowlist(`$nodebin:${FIXED_PATH}`, [], ['CI=true']),
    `"\${pg_env[@]}" "$nodebin/npm" ${which === 'test' ? 'test' : 'run lint'}`,
  ]);
  return [ci, runStep(`pipegen: run the project's ${which} script`, run, {}, `repocode-${sha16(`project-script:${artifact}:${which}`)}`)];
}

// ---------- pip (ruling B5; R-C) ----------

const REQUIREMENT_RE = /^([A-Za-z0-9][A-Za-z0-9._-]{0,100})==([0-9][0-9A-Za-z.+!_-]{0,40})((?: --hash=sha256:[0-9a-f]{64}){1,8})$/;

/** The reviewed closure text, line by line: pinned names, exact versions, sha256 hashes, nothing else. It must hold the tool and every plugin. */
function checkClosure(tool: ReviewedTool, install: InstallSpec, text: string): void {
  const cli = tool.step.cli as NonNullable<typeof tool.step.cli>;
  if (text.length > MAX_TEXT || text.includes(EXPR) || text.includes('\0')) refuse(`The reviewed closure of ${show(tool.id)} is not plain text of at most 64 KiB.`);
  const pins = new Map<string, string>();
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  if (lines.length === 0 || lines.length > 400) refuse(`The reviewed closure of ${show(tool.id)} has no lines or too many.`);
  for (const line of lines) {
    const m = REQUIREMENT_RE.exec(line);
    if (m === null) return refuse(`A line of the reviewed closure of ${show(tool.id)} is not "name==version --hash=sha256:…" (an option, an include, a URL or a missing hash is refused).`);
    pins.set(pep503(m[1] as string), m[2] as string);
  }
  for (const p of [install, ...(cli.plugins ?? [])]) {
    if (!isPypiName(p.package) || pins.get(pep503(p.package)) !== p.version) refuse(`The reviewed closure of ${show(tool.id)} does not pin ${show(p.package)} at ${show(p.version)}.`);
  }
}

/**
 * setup-python (no cache) and a fresh venv that `pip install --require-hashes --no-deps -r` fills from the reviewed
 * closure. Python runs isolated (`-I`: no current-directory or environment imports) from runner temp, never from the
 * workspace, so a repo's venv.py or pip/ folder can't run (review finding 4); only binary wheels are accepted, because
 * an sdist's build dependencies would be installed without hashes.
 */
function pipSteps(tool: ReviewedTool, install: InstallSpec, artifact: string, hooks: CliHooks, closures: Readonly<Record<string, string>>): RenderedStep[] {
  const closure = own(closures, tool.id);
  if (closure === undefined) {
    return refuse(`${show(tool.id)} is not available yet: a pip tool needs a reviewed hash-locked closure of all its dependencies, and none exists (planned for v0.4). Nothing is installed without hashes.`);
  }
  checkClosure(tool, install, closure);
  const req = `$RUNNER_TEMP/pipegen-pip/${artifact}/requirements.txt`;
  const installStep = runStep(`pipegen: install ${tool.step.cli?.command[0] ?? 'tool'} (pip, hashes required)`, script([
    ...prologue(artifact, { discover: ['py="$(command -v python3 || true)"', '[ -n "$py" ] || pg_fail "python3 was not found; the Python setup step must run first"'] }),
    `venv="$RUNNER_TEMP/pipegen-venv/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-pip" "$RUNNER_TEMP/pipegen-venv"',
    `mkdir "$RUNNER_TEMP/pipegen-pip/${artifact}"`,
    `printf '%s' "$PIPEGEN_REQUIREMENTS" > "${req}"`,
    ...allowlist(FIXED_PATH, []),
    'cd "$RUNNER_TEMP"',
    '"${pg_env[@]}" "$py" -I -m venv "$venv"',
    `"\${pg_env[@]}" "$venv/bin/python" -I -m pip install --isolated --no-input --only-binary=:all: --require-hashes --no-deps --no-cache-dir --disable-pip-version-check -r "${req}"`,
  ]), { PIPEGEN_REQUIREMENTS: closure }, `tool-install-${sha16(artifact)}`);
  return [{ ...hooks.setupPython(), id: 'pipegen-setup-python' }, installStep];
}
