// v0.2 Plan G Task 3 (sub-task G6; ruling B4; carries G1-R2 m5/m6, the G1 r1 husky minor, the secrets-hook gap; Plan J ruling G-J1): the
// pre-commit layer, the first of the four (design §2): a secret never enters git history, and format and lint run on the staged files.
//
// pipegen extends the repository's own hook manager by APPENDING its reviewed block to the one file it reads (pre-commit
// `.pre-commit-config.yaml`, husky `.husky/pre-commit`, lefthook `lefthook.yml`); with no manager at all it sets up lefthook (the reviewed one)
// in a new `lefthook.yml`. The user's bytes stay untouched and the exact inserted text is recorded (InstallEdit kind 'hooks'). The text is
// built by hookFile (src/engine/created-builders.ts), the same builder the referee's hook judge rebuilds and compares byte for byte, so what
// this layer proposes is exactly what the judge accepts. B4: no hook repo URL or rev is ever written; a hook runs only a reviewed, pinned
// command:
//   - the secrets hook (always, from the floor's pre-commit secrets need): pipegen at its exact version from npm's registry runs its pinned
//     gitleaks on the staged changes (`pipegen hook secrets`, src/cli/hook.ts); a hook file that already runs a secret scanner gets none;
//   - the format and lint hook (only when the needs list asks for one): the reviewed biome at its reviewed version, from the repository's own
//     install (`npx --no`), so only when the lockfile holds that version; pipegen does not add the devDependency (B2 covers only the test packages).
// The hooks sit where hooks-ci runs them in CI (`pre-commit run --all-files`, `lefthook run pre-commit --all-files`; husky has no CI command).
// The per-repo lefthook `hooks` tuning (npm run <script>, item 63) stays advisory: it never becomes a local hook line.
// `setupCommand` is fixed text per manager (it goes into PIPEGEN.md), never built from repo text or AI text.
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { gitBlobSha } from '../create/guard.js';
import { existingSecretsHook } from '../audit/hook-credit.js';
import { HOOK_FILES, HOOKS_MARKER, hookBlock, hookCommands, hookDataProblem, hookFile, huskyAppendProblem, SECRETS_HOOK_ID, type HookCommand, type HookManager } from '../engine/created-builders.js';
import { parseYaml } from '../engine/yaml-parse.js';
import { readTextLimitedWithReason } from '../read/limits.js';
import type { CreatedFile, InstallEdit, PipelineDraft, ReviewedTool } from '../types.js';

/** G6-R4 HOLE 2: the note next to the canonical gitleaks hook (pipegen's own secrets hook is added all the same). */
const ALSO_SCANS_NOTE = 'Your hooks already run gitleaks; pipegen adds its own secrets hook too, because it also checks files the usual hook skips.';

/** The one command that turns each manager's hooks on in a clone (shown to the user in PIPEGEN.md). Fixed text. */
export const SETUP_COMMANDS: Readonly<Record<HookManager, string>> = Object.freeze({ 'pre-commit': 'pre-commit install', husky: 'npm install', lefthook: 'lefthook install' });

export interface PrecommitResult {
  /** At most one file: the manager's hook file, an edit (`edited.original` is the file as read, '' for a new one). */
  files: CreatedFile[];
  /** The install record's edit of that file (kind 'hooks'): the exact inserted text, the original's blob sha (null: new) and the sha written. */
  edits: InstallEdit[];
  /** SETUP_COMMANDS of the manager written to; '' when no file is written. */
  setupCommand: string;
  /** Plain-English notes for PIPEGEN.md (pipegen's own text; no repo text). */
  notes: string[];
  /**
   * G13-R1 spec I5 (G9-R3 carry 7): the hook file that already holds pipegen's block (a second run): not written again, but set up. `runs`
   * are pipegen's own hook commands (hookCommands) the file holds, never other repo text. `setupCommand` is then the manager's.
   */
  inPlace?: { path: string; runs: string[] }[];
}

/** The note of a husky repository (PIPEGEN.md prints it only when GJ's hooks-ci note for husky is not there: one line per hook manager, G9-R0 3). */
export const HUSKY_NO_CI_NOTE = 'husky hooks are shell scripts, so CI does not re-run them (no hooks-ci command); the CI secret scan still runs on every push.';
const REASON = "pipegen's reviewed pre-commit hooks: a secret scan of the staged changes, and format and lint where the repository asks for it";
const ADVISORY = (scripts: readonly string[]): string => `The per-repo lefthook hooks (${scripts.join(', ')}) stay advisory: they run the repository's own scripts, so pipegen does not add them as local hooks; add them yourself if you want them.`;
const HOOK_SCRIPT_RE = /^[a-z][a-z:-]{0,30}$/;

/** The tuning picks of the hooks-ci lefthook step (item 63), cleaned to plain script names. */
function tunedHookScripts(draft: PipelineDraft): string[] {
  const out: string[] = [];
  for (const s of draft.steps) {
    const picks = s?.tool?.id === 'lefthook' ? s.choices?.tuning?.hooks : undefined;
    if (Array.isArray(picks)) for (const v of picks) if (typeof v === 'string' && HOOK_SCRIPT_RE.test(v) && !out.includes(v)) out.push(v);
  }
  return out;
}

/** The hook file's text as it is now: '' when absent, a note when it can not be read safely (a link, not a file, too large, binary). */
async function readOriginal(dir: string, path: string): Promise<{ text: string } | { note: string }> {
  const full = join(dir, ...path.split('/'));
  try { await lstat(full); } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return { text: '' };
    return { note: `pipegen could not read ${path}, so it adds no hook there` };
  }
  const r = await readTextLimitedWithReason(full, dir);
  if ('text' in r) return r;
  return { note: r.skipped === 'link' ? `${path} is a symbolic link (or sits under one); pipegen never reads or writes through one, so it adds no hook there` : `pipegen could not read ${path} as a plain text file, so it adds no hook there` };
}

/**
 * G17 row 63 (progress l. 411): why a hook file that holds pipegen's block once would not run it, or null. The same checks the write path makes
 * (hookFile), on the file as it is: `before` and `after` are the text around the block. husky: the text before the block passes the append check
 * (no exit or exec, no continued last line, ...); pre-commit and lefthook: the whole file parses strictly as one document, pre-commit's
 * `default_stages` include the commit stage, and, for the block this version writes, the file reads as the rest plus exactly pipegen's hooks.
 */
function inPlaceProblem(manager: HookManager, original: string, before: string, after: string, commands: readonly HookCommand[] | null): string | null {
  if (/[\r\t]/.test(original)) return 'it uses CRLF line ends or tabs';
  if (manager === 'husky') {
    const lines = before.split('\n').filter((l) => l.trim() !== '');
    if (/\\\s*$/.test(lines[lines.length - 1] ?? '')) return 'its line before pipegen\'s block continues onto the next';
    return before.trim() === '' || /^#![^\n]*\n?$/.test(before) ? null : huskyAppendProblem(before);
  }
  const r = parseYaml(original, 'strict');
  if ('problems' in r) return `it does not parse strictly: ${r.problems.join('; ')}`;
  if (manager === 'pre-commit') {
    const ds = (r.parsed.js as Record<string, unknown>).default_stages;
    if (ds !== undefined && !(Array.isArray(ds) && ds.some((x) => x === 'pre-commit' || x === 'commit'))) return 'its `default_stages` leave out the commit stage, so pipegen\'s hooks would not run at commit';
  }
  if (commands !== null) {
    const rest = before + after;
    const p = hookDataProblem(manager, manager === 'pre-commit' && /^repos:[ ]*\n?$/.test(rest) ? '' : rest, original, commands);
    if (p !== null) return p;
  }
  return null;
}

/** Whether another file of the same manager exists (pre-commit and lefthook read other names too; pipegen appends only to its one name). */
async function exists(dir: string, path: string): Promise<boolean> {
  try { await lstat(join(dir, ...path.split('/'))); return true; } catch { return false; }
}
const OTHER_NAMES: Readonly<Record<HookManager, readonly string[]>> = Object.freeze({
  'pre-commit': ['.pre-commit-config.yml'],
  husky: [],
  lefthook: ['lefthook.yaml', '.lefthook.yml', '.lefthook.yaml', '.config/lefthook.yml', '.config/lefthook.yaml', 'lefthook.json', '.lefthook.json', 'lefthook.toml', '.lefthook.toml'],
});

/**
 * The pre-commit layer for `draft` in the repository folder `dir` (read only; nothing is written). `reviewed` is the reviewed list the
 * referee judges with. The plan's signature `(p, choices, dir)` became `(draft, reviewed, dir)`: the hook builder G1 shares with the judge
 * reads the needs, the steps and the reviewed entries.
 */
export async function precommitFiles(draft: PipelineDraft, reviewed: readonly ReviewedTool[], dir: string, recorded: readonly { path: string; inserted: string }[] = []): Promise<PrecommitResult> {
  const notes: string[] = [];
  const none = (note?: string): PrecommitResult => ({ files: [], edits: [], setupCommand: '', notes: note === undefined ? notes : [...notes, note] });
  const tuned = tunedHookScripts(draft);
  if (tuned.length > 0) notes.push(ADVISORY(tuned));
  if (draft.skipped.some((s) => s.part === 'precommit')) return none('You skipped the pre-commit hooks (--skip precommit), so pipegen adds no hook. The CI secret scan and the gate still run.');
  const p = draft.profile;
  if (p.precommit === null && (p.otherHookManagers ?? []).length > 0) return none('The repository uses another hook manager, so pipegen adds no hooks of its own; the CI secret scan and the gate still run.');
  const manager: HookManager = p.precommit ?? 'lefthook';
  const path = HOOK_FILES[manager];
  const read = await readOriginal(dir, path);
  if ('note' in read) return none(read.note);
  const original = read.text;
  if (original === '' && manager !== 'husky') {
    const others = (await Promise.all(OTHER_NAMES[manager].map(async (n) => ((await exists(dir, n)) ? n : null)))).filter((n): n is string => n !== null);
    if (p.precommit !== null || others.length > 0) return none(`pipegen appends its hooks only to ${path}, and this repository keeps its ${manager} config under another name, so pipegen adds no hook; add pipegen's hooks to your config by hand.`);
  }

  // what the builder will leave out, said plainly (G6-R2 spec I3: one true reason each)
  let wanted: string[] = [];
  try { wanted = hookCommands(draft, reviewed).map((c) => c.id); } catch { /* hookFile gives the note */ }
  // G6-R4 HOLE 2: pipegen's own secrets hook is always added; the canonical gitleaks hook only gets a note saying why both run
  if (wanted.includes(SECRETS_HOOK_ID) && existingSecretsHook(manager, original)) notes.push(ALSO_SCANS_NOTE);
  const asksSecrets = draft.needs.some((n) => n.layer === 'pre-commit' && n.id === 'secrets');
  if (asksSecrets && !reviewed.some((t) => t.id === 'gitleaks' && t.categories.includes('secrets'))) notes.push("pipegen's reviewed list has no gitleaks entry here, so it adds no local secrets hook; the CI secret scan still runs on every push.");
  const biome = reviewed.find((t) => t.id === 'biome')?.step.cli?.install;
  const asksFormat = draft.needs.some((n) => n.layer === 'pre-commit' && n.id === 'format-lint') && draft.steps.some((s) => s?.needId === 'format-lint' && s.tool?.id === 'biome');
  if (asksFormat && !wanted.includes('pipegen-biome') && biome !== undefined) {
    notes.push(`The format and lint hook runs the repository's own Biome, so pipegen adds it only when the lockfile holds ${biome.package}@${biome.version}; add that exact devDependency and run pipegen again to get it.`);
  }

  const built = hookFile(manager, original, draft, reviewed);
  if ('note' in built) {
    // spec I5: pipegen's block is already there (an earlier run wrote it): the hooks are set up, nothing is written
    if (original.includes(HOOKS_MARKER)) {
      // ruling G13-R2 2: in place only when the file holds pipegen's exact block once: the block hookBlock writes now (at either pre-commit
      // indentation), or the trusted record's `inserted` text for this path. Anything else (a changed command, commented out, the marker alone,
      // the block twice) is not set up, and says so.
      let commands: HookCommand[] = [];
      try { commands = hookCommands(draft, reviewed); } catch { commands = []; }
      const once = (block: string): boolean => block.trim() !== '' && original.split(block).length === 2;
      const now = commands.length === 0 ? [] : (manager === 'pre-commit' ? ['', '  '] : ['']).map((i) => hookBlock(manager, commands, i));
      const before = recorded.filter((r) => r.path === path).map((r) => r.inserted);
      const block = [...now, ...before].find(once);
      if (block === undefined) return none(`The ${path} file holds a pipegen hooks marker, but what follows it is not pipegen's block as pipegen writes it (changed, commented out, partial or there twice), so pipegen counts these hooks as not set up and adds nothing. Remove pipegen's lines from ${path} and run \`npx pipegen run\` again to have them written.`);
      // G17 row 63: the block is there, but would it run? The write path's checks again, on the file as it is
      const current = now.includes(block);
      const [head, tail] = original.split(block) as [string, string];
      const why = inPlaceProblem(manager, original, head, tail, current ? commands : null);
      if (why !== null) return none(`The ${path} file holds pipegen's hooks block, but pipegen's hooks there would not run as written (${why}), so pipegen counts these hooks as not set up and adds nothing. Fix ${path}, or remove pipegen's lines from it and run \`npx pipegen run\` again to have them written.`);
      const runs = commands.map((c) => c.run).filter((r) => block.includes(r));
      // the note says which block matched: the one this version writes, or the older one the install record holds
      const note = current ? built.note : `${path} holds pipegen's hooks as an earlier version of pipegen wrote them (the install record lists that block), so pipegen counts them as set up and adds nothing; they may differ from the hooks this version would write. Remove pipegen's lines from ${path} and run \`npx pipegen run\` again to get this version's hooks.`;
      return { files: [], edits: [], setupCommand: SETUP_COMMANDS[manager], notes: [...notes, note], inPlace: [{ path, runs }] };
    }
    return none(built.note);
  }
  if (manager === 'husky') notes.push(HUSKY_NO_CI_NOTE);
  const file: CreatedFile = { path, content: built.content, part: 'precommit', reason: REASON, repo: 'app', edited: { original } };
  const edit: InstallEdit = { repo: 'app', path, kind: 'hooks', inserted: built.inserted, originalSha: original === '' ? null : gitBlobSha(original), writtenShas: [gitBlobSha(built.content)] };
  return { files: [file], edits: [edit], setupCommand: SETUP_COMMANDS[manager], notes };
}
