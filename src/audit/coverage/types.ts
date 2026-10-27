// Coverage mapper (see ../coverage.ts for the rules): the types the coverage modules share. Types only: import it with
// `import type`.
import type { Layer, RepoProfile } from '../../types.js';
import type { ScriptClass, Targets } from './scripts.js';
import type { EnvGate } from './settings.js';
import type { ToolSignature } from './signatures.js';
import type { Reader } from './walk.js';
export type { Obj } from '../../read/manifest.js';

/** One way to recognise a command: the first word (or a whole path), then the following words exactly. */
export interface CommandRule { tool: ToolSignature; rest: string[]; excludes: string[][] }
export interface ActionRule { tool: ToolSignature; parts: string[]; prefixLast: boolean }
export interface Compiled {
  byFirstWord: Map<string, CommandRule[]>; byPath: Map<string, CommandRule[]>; actions: ActionRule[];
  /** `hookRepoKey(repo, id)` → the tools a pre-commit hook of that repo and id runs (Task 5). */
  hooks: Map<string, ToolSignature[]>;
  /** The hook repos listed in `precommitHooks` (normalised by hookRepo): pipegen knows what their hooks run. */
  hookRepos: Set<string>;
}

/** Why a run that is found can't block anything (or might not run). */
export type Reason = 'continue' | 'suppressed' | 'function' | 'soft' | 'inputs' | 'no-fail' | 'never' | 'condition'
  | 'hook-repo' | 'files' | 'stage' | 'skip' | 'ref' | 'tox-env' | 'nox-env';

export type Manager = NonNullable<RepoProfile['precommit']>;
export type CiLayer = Exclude<Layer, 'pre-commit'>;
export type Fit = Record<CiLayer, boolean>;

/** A tool found in shell text or a step. `reason` null = it runs and can fail the run. */
export interface Found {
  categories: readonly string[]; by: string; subject: string; dir: string | null; reason: Reason | null; partialWhy?: string;
  /** Task 5: `npm|pnpm|yarn|bun run <script>`, counted only once the script's own text is read (resolveScripts). */
  script?: string;
  /**
   * Task 5: a tox or nox run; an environment variable that picks other envs or sessions (TOX*, NOX*) drops it. 'npm':
   * an npm publish, which NPM_CONFIG_DRY_RUN turns into a dry run (fix round 1, M1).
   */
  envGate?: 'tox' | 'nox' | 'npm';
  /** Fix round 1 (U23): a script counted by name (test, lint[:x]); its text, when readable, can only lower it. */
  byName?: string;
  /** Task 5: `pre-commit run` over all files at the pre-commit stage: the hooks' lint tools run here too (SKIP drops it). */
  hookRun?: boolean;
}
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
  hookRun?: boolean;
}

export interface Budget { visits: number; bytes: number; truncated: boolean }

export interface Ctx {
  p: RepoProfile; sigs: Compiled; read: Reader; budget: Budget; hits: Hit[]; localFiles: Set<string>; unreadable: boolean;
  /** Task 5: package.json files, read through their own Reader so they never use up the workflow reads. */
  pkgRead: Reader;
  pkgScripts: Map<string, Promise<ReadonlyMap<string, string> | null>>;
  /** Task 5: what each (dir, script) runs, worked out once; an entry being worked out is [] (a cycle ends there). */
  scriptMemo: Map<string, Found[]>;
  /** Fix round 2: classifyScript's answer per (dir, script). */
  scriptClass: Map<string, ScriptClass>;
  /** Fix round 3 (N6): the env gate of each local composite action path, worked out once. */
  compositeGates: Map<string, Promise<EnvGate>>;
  /** Fix round 4 (N8): each (dir, script glob)'s matching script names, or 'capped'; and the glob work spent so far. */
  globMemo: Map<string, Targets>;
  globWork: number;
  precommitConfig?: Promise<{ readable: boolean; found: Found[] }>;
}
