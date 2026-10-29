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
// Nothing here uploads (ruling B3) and nothing here fetches rule archives or fills target slots (6c).
import { isDeepStrictEqual } from 'node:util';
import { ArtifactNameError, resultArtifactName } from './artifact-names.js';
import { ASSET_RE, DIGEST_RE, isGitHubRepo, isNpmName, isPypiName, parseImageRef, pep503, SHA256_RE, SRI_SHA512_RE, TAG_RE } from './names.js';
import { RenderError, show } from './render-error.js';
import type { RenderedStep, RenderResult } from './render-step.js';
import { ARGV_POLICIES, PIP_CLOSURES, PLAIN_REL_RE, type ArgvPolicy } from './tool-flags.js';
import type { InstallSpec, ReviewedTool, Service, StepSpec } from '../types.js';

/** Test and internal hooks: the argv policies and the pip closures the renderer reads (production passes neither). */
export interface RenderOptions {
  policies?: Readonly<Record<string, ArgvPolicy>>;
  pipClosures?: Readonly<Record<string, string>>;
}

/** What the CLI renderer needs from render-step.ts (which owns the platform actions and the secret-name rules). */
export interface CliHooks {
  /** The setup-node step for a service's own Node version text (mapped, never rendered raw). */
  setupNode(runtimeVersion: string | undefined): RenderedStep;
  setupPython(): RenderedStep;
  isDangerousName(name: string): boolean;
}

export interface CliArgs { spec: StepSpec; tool: ReviewedTool; service: Service | undefined; hooks: CliHooks; options: RenderOptions }

// ---------- shell text ----------

/** A word that needs no quoting. Plain letters, digits and `_@%+=:,./-`: nothing the shell, a glob or a tilde reads. */
const BARE_RE = /^[A-Za-z0-9_@%+=:,./-]+$/;
const FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const EXPR = '${{';
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,99}$/;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
const EXE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
const PLAIN_OUT_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
const CONFIG_FLAG_RE = /^-{1,2}[A-Za-z][A-Za-z0-9-]{0,40}$/;
const PLACEHOLDER_SPLIT = /(\{[A-Za-z_][A-Za-z0-9_-]{0,63}\})/;
const CHOICE_FLAG_RE = /^[a-z][a-z0-9-]{0,40}$/;
const MAX_TEXT = 64 * 1024;
/** Tool categories that run the project's own code (tests, coverage, image builds): the only steps a declared secret may reach. */
const APP_RUNNING_CATEGORIES: ReadonlySet<string> = new Set(['coverage', 'unit-tests', 'full-tests', 'image-build']);
/** Names the renderer itself puts in a step's env or in the tool's environment; a template env may not use them. */
const RESERVED_ENV = /^(?:HOME|PATH|RUNNER_TEMP|TMPDIR|BASH_ENV|ENV|PIPEGEN_(?:CONFIG|IMAGE|DL_.*|NPM_EXPECT|REQUIREMENTS|ARG_\d+))$/;

const refuse = (message: string): never => { throw new RenderError(message); };
const own = <T>(o: Readonly<Record<string, T>>, k: string): T | undefined => (Object.hasOwn(o, k) ? o[k] : undefined);

/** A reviewed constant as a shell word: bare when plain, else single-quoted (`'` becomes `'\''`). `${{` and NUL are refused. */
function q(s: string): string {
  if (s.includes(EXPR)) return refuse('A reviewed command holds an expression (${{), which Actions would evaluate; pipegen refuses it.');
  if (s.includes('\0')) return refuse('A reviewed command holds a NUL character.');
  return BARE_RE.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

const script = (lines: readonly string[]): string => lines.join('\n');
/** The first lines of every script: fail on any error or unset name, and a message helper. */
const HEAD = ['set -euo pipefail', 'pg_fail() { echo "pipegen: $1" >&2; exit 1; }'] as const;
/** The system tools of a script (curl, tar, find, id, …) are looked up in these folders only, never in a PATH an earlier step changed. */
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
    `cd -- ${q(parts.join('/'))}`,
    'ws="$(cd "$GITHUB_WORKSPACE" && pwd -P)"',
    'case "$(pwd -P)" in "$ws"/*) ;; *) pg_fail "the working folder is outside the repository" ;; esac',
  ];
}

/** The folder `HOME` points at for a tool: fresh, under runner temp, never the runner's own home. */
const homeLines = (artifact: string): string[] => [`home="$RUNNER_TEMP/pipegen-home/${artifact}"`, 'mkdir -p "$RUNNER_TEMP/pipegen-home" "$home"'];

/** The `env -i` array: the only variables a tool sees (ruling S6). `names` are passed through from the step's env by name. */
function allowlist(pathValue: string, names: readonly string[]): string[] {
  return [
    'pg_env=(',
    '  /usr/bin/env -i',
    '  "HOME=$home"',
    `  "PATH=${pathValue}"`,
    '  "RUNNER_TEMP=$RUNNER_TEMP"',
    '  "TMPDIR=$RUNNER_TEMP"',
    ...names.map((n) => `  "${n}=$${n}"`),
    ')',
  ];
}

// ---------- checks on the entry ----------

/** The template env (step.cli.env, equal to fixedInputs.env), each name and value checked. */
function templateEnv(tool: ReviewedTool, hooks: CliHooks): Record<string, string> {
  const env = { ...(tool.step.cli?.env ?? {}) };
  for (const [k, v] of Object.entries(tool.fixedInputs.env ?? {})) {
    if (env[k] !== v) refuse(`The reviewed entry ${show(tool.id)} has an env that disagrees with its fixed inputs.`);
  }
  for (const [k, v] of Object.entries(env)) {
    // PIPEGEN_* names are the renderer's own family (the rules archives of 6c use them); everything else must be harmless to pass on
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

interface Built { main: string[]; then: string[][]; env: Record<string, string> }

/**
 * The words after the executable, as shell words: placeholders become quoted env variables, the pinned config flag goes
 * right after the leading subcommand words (a Go or urfave tool stops reading flags at the first plain word), and a
 * dedicated tool's choices are appended as `--<choice> "$V"` (a bool choice `--<choice>="$V"`).
 */
function buildWords(tool: ReviewedTool, spec: StepSpec, pol: ArgvPolicy, config: PinnedConfig | null, configPath: string | null): Built {
  const cli = tool.step.cli as NonNullable<typeof tool.step.cli>;
  const w: Words = { env: {}, index: new Map() };
  const rest = cli.command.slice(1);
  let lead = 0;
  while (lead < rest.length && !(rest[lead] as string).startsWith('-') && !PLACEHOLDER_SPLIT.test(rest[lead] as string)) lead++;
  if (pol.dedicated !== true && !isDeepStrictEqual(rest.slice(0, lead), pol.sub)) refuse(`The subcommand of ${show(tool.id)} is not the one its argv policy reviewed.`);
  const main = rest.map((x) => wordOf(x, tool, spec, w));
  if (config !== null && configPath !== null) main.splice(lead, 0, q(config.flag), configPath);
  const then = (cli.then ?? []).map((cmd) => {
    if (cmd[0] !== pol.exe) refuse(`A follow-up command of ${show(tool.id)} does not run its own executable.`);
    return cmd.slice(1).map((x) => wordOf(x, tool, spec, w));
  });
  for (const [name, values] of Object.entries(tool.choices)) {
    if (w.index.has(name)) continue;
    if (pol.dedicated !== true) return refuse(`The choice ${show(name)} of ${show(tool.id)} has no place in its command (only a {${name}} placeholder may take it).`);
    if (!CHOICE_FLAG_RE.test(name)) return refuse(`The choice ${show(name)} of ${show(tool.id)} is not a plain flag name.`);
    const v = argVar(w, name, chosenValue(tool, spec, name));
    if (isBoolChoice(values)) main.push(`--${name}=${v}`);
    else main.push(`--${name}`, v);
  }
  return { main, then, env: w.env };
}

// ---------- the main entry ----------

export function renderCliTool({ spec, tool, service, hooks, options }: CliArgs): RenderResult {
  const policies = options.policies ?? ARGV_POLICIES;
  const cli = tool.step.cli;
  if (cli === undefined || tool.candidate.kind === 'action') return refuse(`${show(tool.id)} is not a cli entry.`);
  const pol = own(policies, tool.id);
  if (pol === undefined) return refuse(`${show(tool.id)} has no reviewed argv allowlist, so pipegen won't run it.`);
  if (pol.entrypoint === true) return refuse(`${show(tool.id)} is a job service (the image runs its own entrypoint), not a step; the job composer starts it.`);
  const install = checkInstall(tool, pol);

  // 6c: rule and template archives, and a plugin config that must resolve from the lockfile install
  if (Object.keys(cli.env ?? {}).some((k) => /^PIPEGEN_(?:RULES|NUCLEI)_/.test(k)) || cli.command.some((x) => x.startsWith('/pipegen-') || x.includes('=/pipegen-'))) {
    return refuse(`${show(tool.id)} needs its pinned rules or templates archive, which is rendered in 6c (ruling S12).`);
  }
  if (/(?:^|\n)\s*import\s|\brequire\(/.test(tool.fixedInputs.config?.content ?? '')) {
    return refuse(`${show(tool.id)} has a config that imports a package; it must resolve from the lockfile install, which is rendered in 6c (ruling S11).`);
  }

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

  const config = configOf(tool, pol);
  // where the tool finds its config: the work folder's own file (ZAP reads -c there), a read-only mount, or a file on the runner
  const configPath = config === null ? null : kind !== 'docker' ? `"$cfg/${config.fileName}"` : inWork ? q(config.fileName) : q(`/pipegen-cfg/${config.fileName}`);
  const built = buildWords(tool, spec, pol, config, configPath);
  const tplEnv = templateEnv(tool, hooks);

  const env: Record<string, string> = { ...tplEnv, ...built.env };
  const passed: string[] = Object.keys(env);   // handed to the tool by name through the allowlist
  if (config !== null) env.PIPEGEN_CONFIG = config.content;
  for (const name of secrets) {
    if (!NAME_RE.test(name) || hooks.isDangerousName(name)) return refuse(`The secret name ${show(name)} can't be passed to a tool.`);
    env[name] = `\${{ secrets.${name} }}`;
    passed.push(name);
  }

  const steps: RenderedStep[] = [];
  const discover: string[] = [];       // before PATH is fixed: where node comes from
  const vars: string[] = [];           // names the run line uses
  const prep: string[] = [];           // folders to create
  let prefix: string;                  // the launcher: what comes right before the tool's own words
  let pathValue = FIXED_PATH;

  if (kind === 'github-release') {
    steps.push(releaseInstall(tool, install, exe, artifact));
    vars.push(`bin="$RUNNER_TEMP/pipegen-bin/${artifact}"`);
    prefix = `"$bin/${exe}"`;
  } else if (kind === 'docker') {
    const image = imageOf(tool, install);
    steps.push(runStep(`pipegen: pull the ${exe} image`, script([...HEAD, FIX_PATH, '/usr/bin/docker pull --quiet "$PIPEGEN_IMAGE" > /dev/null']), { PIPEGEN_IMAGE: image }));
    env.PIPEGEN_IMAGE = image;
    const docker = ['/usr/bin/docker', 'run', '--rm', '--pull=never', '--user', '"$(id -u):$(id -g)"', '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL'];
    if (pol.network === 'none') docker.push('--network', 'none');
    const at = (mount as NonNullable<typeof mount>).at;
    if (inWork) {
      vars.push(`work="$RUNNER_TEMP/pipegen-work/${artifact}"`);
      prep.push('mkdir -p "$RUNNER_TEMP/pipegen-work"', 'mkdir "$work"');
      docker.push('-v', `"$work:${at}"`);
    } else docker.push('-v', `"$PWD:${at}"`);
    if (mount?.workdir === true) docker.push('-w', at);
    if (config !== null && !inWork) docker.push('-v', '"$cfg:/pipegen-cfg:ro"');
    for (const n of secrets) docker.push('-e', n);
    docker.push('"$PIPEGEN_IMAGE"', q(exe));
    prefix = docker.join(' ');
  } else if (kind === 'npm') {
    steps.push(...npmSteps(tool, install, artifact, service, spec.workingDir, hooks));
    discover.push(...NODE_LEAD);
    prefix = `"$nodebin/npx" --no-install ${q(exe)}`;
    pathValue = `$nodebin:${FIXED_PATH}`;
  } else {
    steps.push(...pipSteps(tool, install, artifact, hooks, options.pipClosures ?? PIP_CLOSURES));
    vars.push(`venv="$RUNNER_TEMP/pipegen-venv/${artifact}"`);
    prefix = `"$venv/bin/${exe}"`;
    pathValue = `$venv/bin:${FIXED_PATH}`;
  }

  // the pinned config goes in a file the tool is told about (ruling S4)
  const cfgLines = config === null ? [] : inWork
    ? [`printf '%s' "$PIPEGEN_CONFIG" > "$work/${config.fileName}"`]
    : ['mkdir -p "$RUNNER_TEMP/pipegen-cfg"', `cfg="$RUNNER_TEMP/pipegen-cfg/${artifact}"`, 'mkdir "$cfg"', `printf '%s' "$PIPEGEN_CONFIG" > "$cfg/${config.fileName}"`];
  // the result path must be free before the tool runs and a regular file after it (ruling S7)
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
    `  mv -- "$out" "${outDir}/${out}"`,
    'else',
    '  echo "pipegen: the tool left no regular result file at $out" >&2',
    '  if [ "$rc" -eq 0 ]; then rc=1; fi',
    'fi',
  ];
  const launch = (words: readonly string[]): string => `"\${pg_env[@]}" ${prefix}${words.length === 0 ? '' : ` ${words.join(' ')}`}`;
  const chain = [launch(built.main), ...built.then.map(launch)].join(' && ');
  const run = script([
    ...HEAD, ...discover, FIX_PATH, ...vars, ...cdLines(spec.workingDir), ...homeLines(artifact), ...prep, ...cfgLines, ...preCheck,
    ...allowlist(pathValue, passed), 'rc=0', `${chain} || rc=$?`, ...postCheck, 'exit "$rc"',
  ]);
  steps.push(runStep(`pipegen: run ${exe}`, run, env));
  return { steps, output: out === null ? null : { path: `\${{ runner.temp }}/pipegen-out/${artifact}/${out}`, format: tool.step.output.format } };
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
    ...HEAD, FIX_PATH,
    `bin="$RUNNER_TEMP/pipegen-bin/${artifact}"`,
    `dl="$RUNNER_TEMP/pipegen-dl/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-bin" "$RUNNER_TEMP/pipegen-dl"',
    'mkdir "$bin" "$dl"',
    "curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --max-redirs 5 --retry 3 --output \"$dl/asset\" \"$PIPEGEN_DL_URL\"",
    'cd "$dl"',
    "printf '%s  asset\\n' \"$PIPEGEN_DL_SHA256\" | sha256sum --check --strict -",
    ...(archive === null ? [`mv -- "$dl/asset" "$bin/${exe}"`] : [
      'mkdir "$bin/pkg"',
      archive === 'tar' ? 'tar -xzf asset -C "$bin/pkg" --no-same-owner' : 'unzip -q asset -d "$bin/pkg"',
      `n="$(find "$bin/pkg" -name ${q(exe)} -type f | wc -l)"`,
      `o="$(find "$bin/pkg" -name ${q(exe)} ! -type f | wc -l)"`,
      `if [ "$n" -ne 1 ] || [ "$o" -ne 0 ]; then pg_fail "the archive must hold exactly one regular file named ${exe}"; fi`,
      `found="$(find "$bin/pkg" -name ${q(exe)} -type f)"`,
      `mv -- "$found" "$bin/${exe}"`,
    ]),
    `if [ ! -f "$bin/${exe}" ] || [ -L "$bin/${exe}" ]; then pg_fail "the tool is not a regular file"; fi`,
    `chmod 0755 "$bin/${exe}"`,
  ];
  return runStep(`pipegen: install ${exe}`, script(lines), { PIPEGEN_DL_URL: url, PIPEGEN_DL_SHA256: hash });
}

// ---------- docker (ruling S26) ----------

/** The image to run: the entry's own image name at its pinned digest. */
function imageOf(tool: ReviewedTool, install: InstallSpec): string {
  const digest = tool.candidate.pin.digest;
  if (parseImageRef(install.package) === null) return refuse(`The image of ${show(tool.id)} is not a plain image name.`);
  if (digest === undefined || !DIGEST_RE.test(digest)) return refuse(`The pinned digest of ${show(tool.id)} is not a sha256 digest.`);
  return `${install.package}@${digest}`;
}

// ---------- npm (ruling B5) ----------

const NPM_VERSION_RE = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,40})?$/;
/** The lockfile check: the tool and every plugin at the reviewed version and integrity, in the lockfile and installed. A constant, so it can be quoted whole. */
const NPM_CHECK_JS = [
  'const fs = require("fs");',
  'const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));',
  'const want = JSON.parse(process.env.PIPEGEN_NPM_EXPECT);',
  'let bad = 0;',
  'for (const w of want) {',
  '  const p = (lock.packages || {})["node_modules/" + w.name];',
  '  let installed = null;',
  '  try { installed = JSON.parse(fs.readFileSync("node_modules/" + w.name + "/package.json", "utf8")).version; } catch (e) { installed = null; }',
  '  if (!p || p.version !== w.version || p.integrity !== w.integrity || installed !== w.version) {',
  '    console.error("pipegen: " + w.name + " is not the reviewed version " + w.version + " (the lockfile or the installed copy differs)");',
  '    bad = 1;',
  '  }',
  '}',
  'process.exit(bad);',
].join('\n');

/** Where `node` comes from: the folder setup-node put on PATH, read before PATH is fixed. */
const NODE_LEAD = [
  'node="$(command -v node || true)"',
  '[ -n "$node" ] || pg_fail "node was not found; the Node setup step must run first"',
  'nodebin="$(dirname -- "$node")"',
] as const;

/** The tool and every plugin with the exact version and integrity the lockfile must hold. */
function npmPlan(tool: ReviewedTool, install: InstallSpec): { name: string; version: string; integrity: string }[] {
  const cli = tool.step.cli as NonNullable<typeof tool.step.cli>;
  const all: { name: string; version: string; integrity: string | undefined }[] = [
    { name: install.package, version: install.version, integrity: tool.candidate.pin.checksum },
    ...(cli.plugins ?? []).map((p) => ({ name: p.package, version: p.version, integrity: p.checksum })),
  ];
  return all.map((p) => {
    if (!isNpmName(p.name) || !NPM_VERSION_RE.test(p.version) || p.integrity === undefined || !SRI_SHA512_RE.test(p.integrity)) {
      return refuse(`The npm package ${show(p.name)} of ${show(tool.id)} is not a plain name at an exact version with a sha512 integrity.`);
    }
    return { name: p.name, version: p.version, integrity: p.integrity };
  });
}

/** setup-node, one `npm ci --ignore-scripts` per job and folder, and the lockfile check. The first two carry ids so a job keeps one of each (dedupeJobSteps). */
function npmSteps(tool: ReviewedTool, install: InstallSpec, artifact: string, service: Service | undefined, workingDir: string | undefined, hooks: CliHooks): RenderedStep[] {
  const expected = npmPlan(tool, install);
  const exe = tool.step.cli?.command[0] ?? 'tool';
  const dir = (workingDir ?? '').split('/').filter((p) => p !== '' && p !== '.').join('-').replace(/[^A-Za-z0-9_-]/g, '-') || 'root';
  const setup = hooks.setupNode(service?.runtimeVersion);
  const head = (...tail: string[]): string[] => [
    ...HEAD, ...NODE_LEAD, FIX_PATH, ...cdLines(workingDir), ...homeLines(artifact), ...allowlist(`$nodebin:${FIXED_PATH}`, []), ...tail,
  ];
  const ci = runStep('pipegen: install the project dependencies (npm ci, no scripts)', script(head('"${pg_env[@]}" "$nodebin/npm" ci --ignore-scripts --no-audit --no-fund')), {}, `pipegen-npm-ci-${dir}`);
  const check = runStep(`pipegen: check ${exe} against the lockfile`, script(head(
    `js=${q(NPM_CHECK_JS)}`,
    '"${pg_env[@]}" "PIPEGEN_NPM_EXPECT=$PIPEGEN_NPM_EXPECT" "$nodebin/node" -e "$js"',
  )), { PIPEGEN_NPM_EXPECT: JSON.stringify(expected) });
  return [{ ...setup, id: `pipegen-setup-node-${setup.with?.['node-version'] ?? 'default'}` }, ci, check];
}

// ---------- pip (ruling B5) ----------

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

/** setup-python (no cache) and a fresh venv that `pip install --require-hashes --no-deps -r` fills from the reviewed closure. */
function pipSteps(tool: ReviewedTool, install: InstallSpec, artifact: string, hooks: CliHooks, closures: Readonly<Record<string, string>>): RenderedStep[] {
  const closure = own(closures, tool.id);
  if (closure === undefined) {
    return refuse(`${show(tool.id)} is not available yet: a pip tool needs a reviewed hash-locked closure of all its dependencies, and none exists (planned for v0.4). Nothing is installed without hashes.`);
  }
  checkClosure(tool, install, closure);
  const req = `$RUNNER_TEMP/pipegen-pip/${artifact}/requirements.txt`;
  const installStep = runStep(`pipegen: install ${tool.step.cli?.command[0] ?? 'tool'} (pip, hashes required)`, script([
    ...HEAD,
    'py="$(command -v python3 || true)"',
    '[ -n "$py" ] || pg_fail "python3 was not found; the Python setup step must run first"',
    FIX_PATH,
    ...homeLines(artifact),
    `venv="$RUNNER_TEMP/pipegen-venv/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-pip" "$RUNNER_TEMP/pipegen-venv"',
    `mkdir "$RUNNER_TEMP/pipegen-pip/${artifact}"`,
    `printf '%s' "$PIPEGEN_REQUIREMENTS" > "${req}"`,
    ...allowlist(FIXED_PATH, []),
    '"${pg_env[@]}" "$py" -m venv "$venv"',
    `"\${pg_env[@]}" "$venv/bin/python" -m pip install --require-hashes --no-deps --no-cache-dir --disable-pip-version-check -r "${req}"`,
  ]), { PIPEGEN_REQUIREMENTS: closure });
  return [{ ...hooks.setupPython(), id: 'pipegen-setup-python' }, installStep];
}
