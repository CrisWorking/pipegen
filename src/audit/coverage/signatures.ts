// Coverage mapper (see ../coverage.ts for the rules): tool signatures (ruling S1): schema, loader and lookup tables.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { z } from 'zod';
import { NEED_CATEGORIES } from '../../types.js';
import { packageDataPath } from '../../util/package-data.js';
import { safeText } from '../../util/safe-text.js';
import type { ActionRule, CommandRule, Compiled } from './types.js';

// ---------- tool signatures (ruling S1) ----------

const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const PART_RE = /^[A-Za-z0-9_.-]+$/;
const LAST_PART_RE = /^[A-Za-z0-9_.-]+\*?$/;
// Plan P Task 3: a dot in the name for vitest's `--coverage.enabled`
const FLAG_RE = /^-{1,2}[A-Za-z0-9][A-Za-z0-9.-]*(?:=[A-Za-z0-9._-]+)?$/;
const FLAG_NAME_RE = /^-{1,2}[A-Za-z0-9][A-Za-z0-9.-]*$/;
/** Plan P Task 3: a called workflow, exactly owner/repo/.github/workflows/<file>.yml (or .yaml). */
const REUSABLE_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/;
const INPUT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const INPUT_VALUE_RE = /^(?:\*|[a-z0-9._ :/-]{1,64})$/; // ':' and '/' for URL values (repository-url)
/** A pre-commit hook repo, exactly as its README gives it (https://github.com/owner/name). */
const HOOK_REPO_RE = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const HOOK_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const WHY_RE = /^[A-Z][^\n\r]{0,299}\.$/;

/** owner/name, optionally with a sub-path; the last part may end with * (a prefix: snyk/actions/python*). */
function isActionRef(s: string): boolean {
  const parts = s.split('/');
  return s.length <= 200 && parts.length >= 2
    && parts.every((x, i) => (i === parts.length - 1 ? LAST_PART_RE : PART_RE).test(x) && x !== '.' && x !== '..');
}
/** Words of [A-Za-z0-9_.-] separated by one space; the first may be a path ("npm audit", ".husky/pre-commit"). */
function isCommand(s: string): boolean {
  const words = s.split(' ');
  return s.length <= 64 && words.every((x, i) => (i === 0 ? x.split('/').every((p) => PART_RE.test(p)) : PART_RE.test(x)));
}

/** `with:` inputs: name → lowercase values; `*` = any non-empty value. */
const inputs = z.record(z.string().regex(INPUT_RE), z.array(z.string().regex(INPUT_VALUE_RE)).min(1));
const why = z.string().regex(WHY_RE).refine((s) => safeText(s, 300) === s, 'must be plain text');

const signatureSchema = z.strictObject({
  id: z.string().regex(ID_RE),
  categories: z.array(z.enum(NEED_CATEGORIES)).min(1),
  actions: z.array(z.string().refine(isActionRef, 'must be owner/name[/sub]')).min(1).optional(),
  commands: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
  /** Longer commands that start like one of `commands` but are not this check (npm audit signatures, gitleaks version). */
  excludes: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
  /** default: a run fails on findings; flag: only with one of failFlags; never: it only reports. */
  commandFails: z.enum(['default', 'flag', 'never']).optional(),
  failFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Flags that stop a run from failing ("--exit-code=0" also matches "--exit-code 0"); also read in action args inputs. */
  softFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** default: the action fails on findings; input: only with one of failInputs; never: it only reports. */
  actionFails: z.enum(['default', 'input', 'never']).optional(),
  failInputs: inputs.optional(),
  /** `with:` inputs set to one of these values stop the action from failing. */
  softInputs: inputs.optional(),
  /** `with:` inputs set to anything (non-empty) except these values stop the action from failing. */
  softUnless: inputs.optional(),
  /** pipegen's own sentence for a check that never fails the job (commandFails or actionFails never). */
  partialWhy: why.optional(),
  /**
   * Task 5: a command counts only when one of these flags is given (npm publish --provenance). Plan P Task 3 (PS12):
   * matched like notWithFlags (`--cov` also matches `--cov=pkg`), and a value that reads as false (false, 0, null, no,
   * off, empty) never counts.
   */
  onlyWithFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Task 5: a command doesn't count when one of these flags is given (same matching as softFlags). */
  notWithFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Task 5: `with:` inputs set to one of these values (or an expression) mean the action doesn't do this check. */
  skipInputs: inputs.optional(),
  /** Task 5: `with:` inputs set (non-empty) to anything but these values (or an expression) mean the same. */
  skipUnless: inputs.optional(),
  /**
   * Task 5 fix round 1 (C1): the action does this check only from some version on. A `uses:` ref counts when it is one
   * of `moving` (branches that follow the newest release), a tag vX.Y[.Z] or branch release/vX.Y at or above
   * `minVersion`, or a commit SHA in `shas`; a version below `minVersion` doesn't count (missing, `oldWhy`); any other
   * ref (an unknown SHA, main, an expression) is partial (`unknownWhy`).
   */
  actionRef: z.strictObject({
    moving: z.array(z.string().regex(/^[A-Za-z0-9._/-]{1,64}$/)).min(1),
    minVersion: z.tuple([z.number().int().min(0), z.number().int().min(0)]),
    shas: z.array(z.string().regex(/^[0-9a-f]{40}$/)).min(1),
    oldWhy: why,
    unknownWhy: why,
  }).optional(),
  /** Task 5: pre-commit hooks that run this tool: the hook repo (exact URL) and its hook ids. */
  precommitHooks: z.array(z.strictObject({ repo: z.string().regex(HOOK_REPO_RE), ids: z.array(z.string().regex(HOOK_ID_RE)).min(1) })).min(1).optional(),
  /**
   * Plan P Task 3: called workflows (a job-level `uses:`) that run this tool, matched exactly like `actions` (letter
   * case and the @ref ignored) and read like an action: their job-level `with:` inputs count. A ref that is neither a
   * commit SHA nor a vX[.Y[.Z]] tag is partial ('ref').
   */
  reusableWorkflows: z.array(z.string().max(200).regex(REUSABLE_RE)).min(1).optional(),
  /**
   * Plan P Task 3: a command counts only when `flag` is given (`--f v` or `--f=v`, the last one wins) with a non-empty
   * value that, with `contains`, includes that word once split at commas; an action only when its `input` does. With
   * `ifGiven`, leaving the flag or input out is fine (the tool's default does the check) but a value without the word
   * doesn't count, and neither does a command line longer than pipegen reads.
   */
  onlyWithFlagValue: z.strictObject({
    flag: z.string().regex(FLAG_NAME_RE).optional(),
    input: z.string().regex(INPUT_RE).optional(),
    contains: z.string().regex(/^[a-z0-9._-]{1,32}$/).optional(),
    ifGiven: z.literal(true).optional(),
  }).refine((v) => v.flag !== undefined || v.input !== undefined, 'needs flag or input').optional(),
  /**
   * Plan P Task 3: the action does this check only when one of these inputs is set to one of the values (`*` = any
   * non-empty value), in every spelling; an expression doesn't count.
   */
  onlyWithInputs: inputs.optional(),
  /**
   * Plan P Task 3 (ruling R4, PS16): who can use the action. `public`: public repos only; `public-or-code-security`:
   * public repos, and organisation-owned private repos with code scanning. Elsewhere a run is partial with
   * `unavailableWhy`.
   */
  availability: z.enum(['public', 'public-or-code-security']).optional(),
  unavailableWhy: why.optional(),
  /**
   * Plan P Task 3 (ruling PB5): inputs that must hold for the action to do the check. `all`: every listed input is set
   * to one of its values in every spelling; `any`: at least one listed input is; `unset`: none of these is set (to
   * anything but "false"). An unset input, an expression or another value gives partial with `why`.
   */
  requireInputs: z.strictObject({
    all: inputs.optional(),
    any: inputs.optional(),
    unset: z.array(z.string().regex(INPUT_RE)).min(1).optional(),
    why,
  }).refine((r) => r.all !== undefined || r.any !== undefined || r.unset !== undefined, 'needs all, any or unset').optional(),
  /**
   * Plan P Task 3 (ruling PB3): what the command must scan to count. `image`: its arguments name a container image
   * (an image scheme such as registry: or docker:, or a name with a :tag or @sha256 digest) and no folder; `folder`:
   * they name a folder, file or SBOM (dir:, file:, sbom:, `--from dir`, a path). A run that names neither is partial
   * ('target').
   */
  scanTarget: z.enum(['image', 'folder']).optional(),
})
  .refine((t) => t.commandFails !== 'flag' || t.failFlags !== undefined, { message: 'commandFails: flag needs failFlags' })
  .refine((t) => t.actionFails !== 'input' || t.failInputs !== undefined, { message: 'actionFails: input needs failInputs' })
  .refine((t) => t.excludes === undefined || t.commands !== undefined, { message: 'excludes needs commands' })
  .refine((t) => (t.onlyWithFlags === undefined && t.notWithFlags === undefined) || t.commands !== undefined, { message: 'onlyWithFlags and notWithFlags need commands' })
  .refine((t) => (t.skipInputs === undefined && t.skipUnless === undefined) || t.actions !== undefined, { message: 'skipInputs and skipUnless need actions' })
  .refine((t) => t.actionRef === undefined || t.actions !== undefined, { message: 'actionRef needs actions' })
  .refine((t) => t.actions !== undefined || t.commands !== undefined || t.reusableWorkflows !== undefined, { message: 'needs actions, commands or reusableWorkflows' })
  .refine((t) => t.onlyWithFlagValue?.flag === undefined || t.commands !== undefined, { message: 'onlyWithFlagValue.flag needs commands' })
  .refine((t) => t.onlyWithFlagValue?.input === undefined || t.actions !== undefined, { message: 'onlyWithFlagValue.input needs actions' })
  .refine((t) => (t.onlyWithInputs === undefined && t.requireInputs === undefined && t.availability === undefined) || t.actions !== undefined || t.reusableWorkflows !== undefined,
    { message: 'onlyWithInputs, requireInputs and availability need actions or reusableWorkflows' })
  .refine((t) => (t.availability === undefined) === (t.unavailableWhy === undefined), { message: 'availability and unavailableWhy go together' })
  .refine((t) => t.scanTarget === undefined || t.commands !== undefined, { message: 'scanTarget needs commands' });

const signaturesSchema = z.strictObject({ tools: z.array(signatureSchema).min(1) })
  .refine((f) => new Set(f.tools.map((t) => t.id)).size === f.tools.length, { message: 'ids must be unique' });

export type ToolSignature = z.infer<typeof signatureSchema>;

/** Reads and checks the tool signatures (default: pipegen's own data/tool-signatures.yml). Throws on any problem. */
export function loadToolSignatures(path: string = packageDataPath('tool-signatures.yml')): ToolSignature[] {
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new Error(`pipegen's tool signatures (${path}) could not be read: ${e instanceof Error ? e.message.split('\n')[0] : 'unreadable'}`);
  }
  const parsed = signaturesSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`pipegen's tool signatures (${path}) are not valid: ${issue?.path.join('.') || 'file'}: ${issue?.message ?? 'invalid'}`);
  }
  return parsed.data.tools;
}

/** A pre-commit `repo:` URL compared exactly, ignoring letter case, a trailing slash and a trailing .git. */
export const hookRepo = (repo: string) => repo.trim().toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
export const hookRepoKey = (repo: string, id: string) => `${hookRepo(repo)}\u0000${id}`;

export function compile(tools: ToolSignature[]): Compiled {
  const byFirstWord = new Map<string, CommandRule[]>();
  const byPath = new Map<string, CommandRule[]>();
  const actions: ActionRule[] = [];
  const hooks = new Map<string, ToolSignature[]>();
  const hookRepos = new Set<string>();
  const reusable = new Map<string, ToolSignature[]>();
  for (const tool of tools) {
    for (const w of tool.reusableWorkflows ?? []) reusable.set(w.toLowerCase(), [...(reusable.get(w.toLowerCase()) ?? []), tool]);
    for (const h of tool.precommitHooks ?? []) {
      hookRepos.add(hookRepo(h.repo));
      for (const id of h.ids) hooks.set(hookRepoKey(h.repo, id), [...(hooks.get(hookRepoKey(h.repo, id)) ?? []), tool]);
    }
    for (const cmd of tool.commands ?? []) {
      const [first, ...rest] = cmd.split(' ') as [string, ...string[]];
      const excludes = (tool.excludes ?? []).map((e) => e.split(' ')).filter((e) => e[0] === first && e.length > 1).map((e) => e.slice(1));
      const rule: CommandRule = { tool, rest, excludes };
      // A command whose first word is a path (.husky/pre-commit) matches the whole path; any other its basename.
      const map = first.includes('/') ? byPath : byFirstWord;
      map.set(first, [...(map.get(first) ?? []), rule]);
    }
    for (const a of tool.actions ?? []) {
      const parts = a.toLowerCase().split('/');
      const last = parts[parts.length - 1] as string;
      const prefixLast = last.endsWith('*');
      if (prefixLast) parts[parts.length - 1] = last.slice(0, -1);
      actions.push({ tool, parts, prefixLast });
    }
  }
  return { byFirstWord, byPath, actions, hooks, hookRepos, reusable };
}

export const PRE_COMMIT_ID = 'pre-commit';
