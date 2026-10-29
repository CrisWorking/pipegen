// Coverage mapper (see ../coverage.ts for the rules): the types the coverage modules share. Types only: import it with
// `import type`.
import type { Capabilities, Layer, RepoProfile } from '../../types.js';
import type { ComposeModel, DockerLoad } from './docker.js';
import type { ScriptClass, Targets } from './scripts.js';
import type { EnvGate, SkipSet } from './settings.js';
import type { ToolSignature } from './signatures.js';
import type { Reader } from './walk.js';
export type { Obj } from '../../read/manifest.js';

/** One way to recognise a command: the first word (or a whole path), then the following words exactly. */
export interface CommandRule { tool: ToolSignature; rest: string[]; excludes: string[][] }
export interface ActionRule { tool: ToolSignature; parts: string[]; prefixLast: boolean }
export interface Compiled {
  byFirstWord: Map<string, CommandRule[]>; byPath: Map<string, CommandRule[]>; actions: ActionRule[];
  /** Plan P Task 3: `owner/repo/.github/workflows/<file>` (lowercase) → the tools a job-level `uses:` of it runs. */
  reusable: Map<string, ToolSignature[]>;
  /** Fix round 1 (P8): every signature's softEnv names, looked for once per job; fix round 2: and their configFiles names. */
  softEnv: readonly string[];
  configFiles: readonly string[];
  /** `hookRepoKey(repo, id)` → the tools a pre-commit hook of that repo and id runs (Task 5). */
  hooks: Map<string, ToolSignature[]>;
  /** The hook repos listed in `precommitHooks` (normalised by hookRepo): pipegen knows what their hooks run. */
  hookRepos: Set<string>;
}

/** Why a run that is found can't block anything (or might not run). */
export type Reason = 'continue' | 'suppressed' | 'function' | 'soft' | 'inputs' | 'no-fail' | 'never' | 'condition'
  // P51: in a followed repo script, the check runs only under a condition (if/case/while, a test's && or ||, after a conditional exit)
  | 'script-condition'
  // P53: the same, in a workflow step's run:, a package script or a hook file
  | 'shell-condition'
  | 'hook-repo' | 'files' | 'stage' | 'skip' | 'changed' | 'ref' | 'tox-env' | 'nox-env'
  // P59 (2): a CI hook run limited to part of the repo (prek --directory / --glob, a --files list)
  | 'part'
  // Plan P Task 3: an action this repo can't use (availability), an action not set up for the check (requireInputs),
  // egress control missing from some release jobs (PB5), a scan target pipegen can't place (imageArg), a command with
  // more words than pipegen reads
  | 'unavailable' | 'needs-inputs' | 'some-jobs' | 'target' | 'long'
  // fix round 1: a config file or env var that can turn the check off (P8); an egress step on a runner it can't guard
  | 'config' | 'runner'
  // Plan P final review I1 (ruling P33): an action on pipegen's own never-list, which never makes a row covered
  | 'never-listed';

export type Manager = NonNullable<RepoProfile['precommit']>;
export type CiLayer = Exclude<Layer, 'pre-commit'>;
/**
 * The triggers a run is on. `scheduled` (Plan P Task 3): a `schedule` event or a push to the default branch, the right
 * trigger for the scheduled checks (SCHEDULED_CATEGORIES), which are merge-layer needs.
 */
export type Slot = CiLayer | 'scheduled';
export type Fit = Record<Slot, boolean>;

/** One Dockerfile a command builds (repo-relative, plain paths), its build context, and the --target stage ('' = none). */
export interface DockerBuild {
  file: string; context: string; target: string | null;
  /** P57 (M1, M3): why pipegen can't tell what this build runs (a flag it doesn't know, a custom frontend, a path it can't place): unknown. */
  unsure?: string;
}

/** A tool found in shell text or a step. `reason` null = it runs and can fail the run. */
export interface Found {
  categories: readonly string[]; by: string; subject: string; dir: string | null; reason: Reason | null; partialWhy?: string;
  /** Task 5: `npm|pnpm|yarn|bun run <script>`, counted only once the script's own text is read (resolveScripts). */
  script?: string;
  /** DoD run (fastapi): a shell script file of the repo (repoScriptFile), relative to `dir`, followed by resolveScripts. */
  scriptFile?: string;
  /** P52 (e): the script file is run directly (not after `bash|sh`), so its shebang decides what runs. */
  scriptDirect?: boolean;
  /**
   * Task 5: a tox or nox run; an environment variable that picks other envs or sessions (TOX*, NOX*) drops it. 'npm':
   * an npm publish, which NPM_CONFIG_DRY_RUN turns into a dry run (fix round 1, M1).
   */
  envGate?: 'tox' | 'nox' | 'npm' | 'pytest';
  /** Fix round 1 (U23): a script counted by name (test, lint[:x]); its text, when readable, can only lower it. */
  byName?: string;
  /**
   * Task 5: `pre-commit run` (or prek) over all files at the pre-commit stage: the hooks' lint tools run here too (SKIP
   * drops it). P55 (batch B): 'changed' = it runs over the files between two refs only (`--from-ref … --to-ref …`), so
   * those tools are carried as partial ('changed').
   */
  hookRun?: boolean | 'changed' | 'part';
  /**
   * P55 (batch B): `docker build`, docker/build-push-action or `docker compose build` builds these images, so the RUN lines
   * of their Dockerfiles run in CI (read by resolveScripts, docker.ts): one Dockerfile and its context, or the services of
   * a compose file (all of them when `services` is null), found from the folder `cwd`.
   */
  dockerBuild?: DockerBuild;
  composeBuild?: { files: readonly string[] | null; cwd: string; services: readonly string[] | null; shellReason: Reason | null; profiles: readonly string[]; unsure: string | null };
  /** P55 (batch B): this command runs inside the compose service `service` (`docker compose run|exec`), so its folder is that service's build context. */
  composeRun?: { files: readonly string[] | null; cwd: string; service: string; unsure: string | null };
  /** P57 (C3): found inside a compose service (compose run/exec, or a RUN line of a Dockerfile compose builds), so a COMPOSE_FILE or COMPOSE_PROFILES variable can change it. */
  compose?: true;
  /** Plan P Task 3 (PS14): a pre-commit formatter hook that writes files or checks them, so a CI `pre-commit run` fails on a change. */
  formats?: boolean;
  /** Fix round 1 (P8): the tool's softEnv names and the config files it loads (none when its config flag turned them off). */
  softEnv?: readonly string[];
  configFiles?: readonly string[];
  /** Fix round 1: the job env a CI `pre-commit run` sees, so the hooks' tools carried there check their softEnv against it. */
  jobEnv?: JobEnv;
  /**
   * P57 (C1): the service languages the run checks (src/types.ts Language); absent = any language. '?' = pipegen can't
   * tell (an own script whose runner it doesn't know): the run is at most partial for a service of a language not listed.
   */
  langs?: readonly string[];
  /** P57 (C1): the folders the tool was given as path arguments (repo-relative); the run covers only the services under them. */
  pathArgs?: readonly string[];
  /** P59 (3): the run was given a path pipegen can't place: why (it can't cover a service, only be unknown there). */
  unplaced?: string;
  /** P57 (C4): the pre-commit hook id this run comes from (readPrecommitConfig), so SKIP / PREK_SKIP can name it. */
  hookId?: string;
  /** P57 (C4): the hook's `alias`, which SKIP / PREK_SKIP may name instead of its id. */
  hookAlias?: string;
  /** P57 (C4): a CI pre-commit/prek run's SKIP set (gated): the hooks it names are partial, an unreadable one makes all unknown. */
  hookSkip?: SkipSet;
}
/** Fix round 1 (P8): the softEnv names set in a job (`all`: an `env:` given as one expression could set any). */
export interface JobEnv { all: boolean; names: ReadonlySet<string>; files: ReadonlySet<string> }
export interface Hit {
  opaque: boolean;
  categories: readonly string[];
  by?: string;
  subject: string;
  dir: string | null;
  reason: Reason | null;
  partialWhy?: string;
  fit: Fit;
  where: string;
  why?: string;
  hookRun?: boolean | 'changed' | 'part';
  /** Plan P Task 3 (PB5): found in a local composite action's later step, so not the first step of its job. */
  laterStep?: boolean;
  /** Fix round 1: config files the tool loads by itself (checked for after the walk), and a CI pre-commit run's job env. */
  configFiles?: readonly string[];
  jobEnv?: JobEnv;
  /** Fix round 2: the run's job may be on macOS or Windows, where config file names match in any letter case. */
  foldCase?: boolean;
  /** P57 (C1): Found.langs and Found.pathArgs. */
  langs?: readonly string[];
  pathArgs?: readonly string[];
  /** P57 (C4): Found.hookSkip. */
  hookSkip?: SkipSet;
  /** P59 (3): Found.unplaced. */
  unplaced?: string;
}

export interface Budget { visits: number; bytes: number; truncated: boolean }

export interface Ctx {
  p: RepoProfile; sigs: Compiled; read: Reader; budget: Budget; hits: Hit[]; localFiles: Set<string>; unreadable: boolean;
  /** Task 5: package.json files, read through their own Reader so they never use up the workflow reads. */
  pkgRead: Reader;
  pkgScripts: Map<string, Promise<ReadonlyMap<string, string> | null>>;
  /** Task 5: what each (dir, script) runs, worked out once; an entry being worked out is [] (a cycle ends there). */
  scriptMemo: Map<string, Found[]>;
  /** P50 (C2): the reader for repo shell script files, apart from pkgRead, and how many script files were tried (failed ones too). */
  scriptRead: Reader;
  scriptFileReads: number;
  /** Fix round 2: classifyScript's answer per (dir, script). */
  scriptClass: Map<string, ScriptClass>;
  /** Fix round 3 (N6): the env gate of each local composite action path, worked out once. */
  compositeGates: Map<string, Promise<EnvGate>>;
  /** Fix round 4 (N8): each (dir, script glob)'s matching script names, or 'capped'; and the glob work spent so far. */
  globMemo: Map<string, Targets>;
  globWork: number;
  /** Plan P Task 3: what GitHub allows here (MapCoverageOptions.capabilities); absent = no code scanning. */
  caps?: Capabilities;
  /**
   * Fix round 1 (P8, concern 2): every job of every release workflow (its first-step hit range and `where`), and whether
   * some release workflow couldn't be walked in full. Egress is decided over all of them.
   */
  releaseJobs: { start: number; first: number; where: string }[];
  releaseUnread: boolean;
  precommitConfig?: Promise<{ readable: boolean; found: Found[] }>;
  /** P57 (C4): prek.toml, which prek reads before .pre-commit-config.yaml: absent, unreadable, or its hooks. */
  prekConfig?: Promise<'absent' | 'unreadable' | Found[]>;
  /** P55 (batch B): each compose file set's services, worked out once (docker.ts). */
  composeMemo: Map<string, ComposeModel>;
  /** P55 (batch B): each Dockerfile's parse, worked out once (docker.ts). */
  dockerParsed: Map<string, DockerLoad>;
}
