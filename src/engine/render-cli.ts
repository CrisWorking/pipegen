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
// - The result file is checked before and after the tool, and moved under `$RUNNER_TEMP/pipegen-out/<artifact>/` (ruling S7).
// - The pinned config is written from an env variable with `printf '%s'`, never a heredoc, to a file name the argv policy
//   chose (ruling S4). The repo's own config files are never named.
// - Rule archives (semgrep rules, nuclei templates) are fetched by commit and checked by tree (ruling S12), and the values a
//   tool needs at run time (image, local URL, Dockerfile, base ref) are slots from the render context (ruling B6): slots.ts.
// Nothing here uploads (ruling B3).
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { ArtifactNameError, resultArtifactName } from './artifact-names.js';
import { ASSET_RE, COMMIT_SHA_RE, DIGEST_RE, isGitHubRepo, isNpmName, isPypiName, parseImageRef, pep503, SHA256_RE, SRI_SHA512_RE, TAG_RE } from './names.js';
import { closureRootDependencies, loadNpmClosure, NpmClosureError, type NpmPin } from './npm-closure.js';
import { EXPR, own, refuse, show } from './render-error.js';
import type { RenderContext, RenderedStep, RenderResult } from './render-step.js';
import { slotProblem, type SlotKind } from './slots.js';
import { ARGV_POLICIES, PIP_CLOSURES, PLAIN_REL_RE, type ArgvPolicy } from './tool-flags.js';
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
const RESERVED_ENV = /^(?:HOME|PATH|RUNNER_TEMP|TMPDIR|BASH_ENV|ENV|PIPEGEN_(?:CONFIG|IMAGE|DL_.*|NPM_EXPECT|REQUIREMENTS|RULES_(?:REMOTE|COMMIT|TREE_WANT)|ARG_\d+))$/;


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
function allowlist(pathValue: string, names: readonly string[], constants: readonly string[] = []): string[] {
  for (const c of constants) if (!/^[A-Z][A-Z0-9_]{0,40}=[A-Za-z0-9_.-]{0,40}$/.test(c)) refuse('A constant of the tool environment is not a plain NAME=value.');
  return [
    'pg_env=(',
    '  /usr/bin/env -i',
    '  "HOME=$home"',
    `  "PATH=${pathValue}"`,
    '  "RUNNER_TEMP=$RUNNER_TEMP"',
    '  "TMPDIR=$RUNNER_TEMP"',
    ...constants.map((c) => `  "${c}"`),
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
function buildWords(tool: ReviewedTool, spec: StepSpec, pol: ArgvPolicy, config: PinnedConfig | null, configPath: string | null, slots: Slot[]): Built {
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

// ---------- the main entry ----------

const sha16 = (text: string): string => createHash('sha256').update(text).digest('hex').slice(0, 16);
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
    artifact = resultArtifactName(spec.needId, spec.service);
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
  const built = buildWords(tool, spec, pol, config, configPath, slots);
  const tplEnv = templateEnv(tool, hooks);

  const env: Record<string, string> = { ...tplEnv, ...built.env };
  const archive = pol.archive;
  const passed: string[] = Object.keys(env);   // handed to the tool by name through the allowlist
  if (config !== null) env.PIPEGEN_CONFIG = config.content;
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
    prefix = `"$bin/${exe}"`;
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
  const cfgLines = config === null ? [] : checker || inWork
    ? [`printf '%s' "$PIPEGEN_CONFIG" > "${cfgBase}/${config.fileName}"`]
    : ['mkdir -p "$RUNNER_TEMP/pipegen-cfg"', `cfg="$RUNNER_TEMP/pipegen-cfg/${artifact}"`, 'mkdir "$cfg"', `printf '%s' "$PIPEGEN_CONFIG" > "$cfg/${config.fileName}"`];
  // the result path must be free before the tool runs and a regular file after it, also where it lands (ruling S7)
  const outDir = `$RUNNER_TEMP/pipegen-out/${artifact}`;
  const preCheck = out === null ? [] : [
    inWork ? `out="$work/${out}"` : `out=${q(out)}`,
    inWork ? 'outdir="$work"' : 'outdir=.',
    'if [ -e "$out" ] || [ -L "$out" ]; then pg_fail "the result file $out exists before the tool ran, so pipegen will not use it"; fi',
    '[ -d "$outdir" ] && [ ! -L "$outdir" ] || pg_fail "the folder for the result is not a real folder"',
  ];
  const postCheck = out === null ? [] : [
    'if [ -f "$out" ] && [ ! -L "$out" ]; then',
    '  mkdir -p "$RUNNER_TEMP/pipegen-out"',
    `  mkdir "${outDir}"`,
    `  dest="${outDir}/${out}"`,
    '  mv -- "$out" "$dest"',
    '  [ -f "$dest" ] && [ ! -L "$dest" ] || { rm -f -- "$dest"; rc=1; }',
    // a speed bump, not a guard (review-6b-r2 C3): a later step of the same user can chmod it back
    `  chmod -R a-w "${outDir}"`,
    'else',
    '  echo "pipegen: the tool left no regular result file at $out" >&2',
    '  if [ "$rc" -eq 0 ]; then rc=1; fi',
    'fi',
  ];
  const launch = (words: readonly string[]): string => `"\${pg_env[@]}" ${prefix}${words.length === 0 ? '' : ` ${words.join(' ')}`}`;
  const chain = [launch(built.main), ...built.then.map(launch)].join(' && ');
  const run = script([
    ...prologue(artifact, nodeMajor === undefined ? {} : { nodeMajor }), ...vars, ...installLines, ...cdLines(spec.workingDir), ...pathChecks, ...prep, ...cfgLines, ...preCheck,
    ...closureVars, ...allowlist(pathValue, passed), ...afterAllow, 'rc=0', `${chain} || rc=$?`, ...postCheck, 'exit "$rc"',
  ]);
  // a tool that runs the repo's own code is marked, so the referee can apply its order rule (S6 c); the id is not `pipegen-…`, which a job's dedupe may drop
  // fail closed: the run is repo code unless the policy says it only reads (readsOnly), and never for an app-running category
  const appRunning = tool.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
  const harmless = pol.readsOnly === true && pol.runsRepoCode !== true && pol.loadsRepoConfig !== true && !appRunning;
  const runId = !harmless ? `repocode-${sha16(artifact)}` : checker ? `checker-run-${sha16(artifact)}` : `tool-run-${sha16(artifact)}`;
  steps.push(runStep(`pipegen: run ${exe}`, run, env, runId));
  return { steps, output: out === null ? null : { path: `\${{ runner.temp }}/pipegen-out/${artifact}/${out}`, format: tool.step.output.format }, ...(built.fullHistory ? { fullHistory: true as const } : {}) };
}

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

/** The static check of a repo lockfile, run BEFORE `npm ci`: the tool and its plugins are plain registry packages at the reviewed version and integrity, and no shrinkwrap overrides the lockfile. */
const NPM_PRECHECK_JS = [
  'const fs = require("fs");',
  'let sw = null;',
  'try { sw = fs.lstatSync("npm-shrinkwrap.json"); } catch (e) { sw = null; }',
  'if (sw) { console.error("pipegen: npm-shrinkwrap.json takes precedence over package-lock.json; pipegen will not install with it"); process.exit(1); }',
  'const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));',
  'const want = JSON.parse(process.env.PIPEGEN_NPM_EXPECT);',
  'let bad = 0;',
  'for (const w of want) {',
  '  const p = (lock.packages || {})["node_modules/" + w.name];',
  '  if (!p || p.link || p.inBundle || (p.name && p.name !== w.name) || p.version !== w.version || p.resolved !== w.resolved || p.integrity !== w.integrity) {',
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
