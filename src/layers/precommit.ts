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
import { HOOK_FILES, HOOKS_MARKER, hookCommands, hookFile, SECRETS_HOOK_ID, type HookManager } from '../engine/created-builders.js';
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
export async function precommitFiles(draft: PipelineDraft, reviewed: readonly ReviewedTool[], dir: string): Promise<PrecommitResult> {
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
      let runs: string[] = [];
      try { runs = hookCommands(draft, reviewed).map((c) => c.run).filter((r) => original.includes(r)); } catch { runs = []; }
      return { files: [], edits: [], setupCommand: SETUP_COMMANDS[manager], notes: [...notes, built.note], inPlace: [{ path, runs }] };
    }
    return none(built.note);
  }
  if (manager === 'husky') notes.push(HUSKY_NO_CI_NOTE);
  const file: CreatedFile = { path, content: built.content, part: 'precommit', reason: REASON, repo: 'app', edited: { original } };
  const edit: InstallEdit = { repo: 'app', path, kind: 'hooks', inserted: built.inserted, originalSha: original === '' ? null : gitBlobSha(original), writtenShas: [gitBlobSha(built.content)] };
  return { files: [file], edits: [edit], setupCommand: SETUP_COMMANDS[manager], notes };
}
