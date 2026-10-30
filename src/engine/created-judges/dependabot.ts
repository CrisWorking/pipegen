// The dependabot.yml judge (v0.2 Plan D, D0b; preflight 4.2). A wrong file can turn updates off or swap the registry. The rule:
// the user's content is untouched (parsed data deep-equal), exactly one entry is appended, and it equals dependabotEntry(draft).
// A repo that uses Renovate gets no file; a repo that already has a `github-actions` entry for `/` gets none either (Dependabot rejects
// a duplicate and then stops ALL updates, so pipegen never edits the user's entry and adds nothing).
import { isDeepStrictEqual } from 'node:util';
import { dependabotEntry } from '../created-builders.js';
import type { CreatedCtx } from '../created-files.js';
import type { CreatedFile } from '../../types.js';
import { isObj, parseYaml, type Obj } from '../yaml-parse.js';

const PLACES = ['.github/dependabot.yml', '.github/dependabot.yaml'];
/** Keys that, set by pipegen's entry, would turn updates off, swap a registry, run code, move the target or widen what is ignored. */
const WHY: Record<string, string> = {
  registries: 'it can swap the registry', 'insecure-external-code-execution': 'it lets update code run', 'open-pull-requests-limit': 'it can turn version updates off',
  'target-branch': 'it moves the updates to another branch', vendor: 'it changes what is vendored', 'enable-beta-ecosystems': 'it turns on unreviewed ecosystems', ignore: 'it can switch off security updates',
  allow: 'it narrows what is updated', 'rebase-strategy': 'it can stop rebases', 'commit-message': 'it changes the commit text', labels: 'pipegen sets none', assignees: 'it assigns people', reviewers: 'it assigns people',
};

const rootish = (d: unknown): boolean => typeof d !== 'string' || /^\.?\/*$/.test(d.trim()) || d.includes('*');

/** An entry that updates `/`: `directory`, or any of `directories` (a glob, or a value that is not text, counts: it may include `/`). A target branch does not make it different. */
const coversRoot = (u: Obj): boolean => (u.directory !== undefined && rootish(u.directory)) || (u.directories !== undefined && (!Array.isArray(u.directories) || u.directories.some(rootish)));

function load(text: string, label: string, out: string[]): Obj | null {
  const r = parseYaml(text, 'strict');
  if ('problems' in r) { out.push(`${label}: ${r.problems.join('; ')}`); return null; }
  return r.parsed.js;
}

export function dependabotJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  const { draft } = ctx;
  const rf = draft.profile.repoFiles;
  if (rf.renovate !== null) return ['this repository uses Renovate (a Renovate config exists), which keeps its own update settings, so pipegen writes no dependabot.yml'];
  if (rf.dependabot !== null && !PLACES.includes(rf.dependabot)) return ['the existing Dependabot path is not one GitHub reads'];
  const want = rf.dependabot ?? '.github/dependabot.yml';
  if (file.path !== want) return [`the Dependabot file is ${want}${rf.dependabot === null ? ' (none exists yet)' : ' (the one that exists; GitHub reads one of the two spellings, never both)'}, not ${file.path}`];
  const original = file.edited?.original;
  if (typeof original !== 'string') return ['the edited marker with the original text is missing'];
  if (rf.dependabot === null && original !== '') return ['no Dependabot file exists, but an original text was given'];
  if (rf.dependabot !== null && original.trim() === '') return ['a Dependabot file exists, but the original text given is empty: writing would replace the user\'s file'];
  const exprs = (t: string): number => t.split('${{').length - 1;
  // a new file is all pipegen's; in an edit the user's own text may hold one (a token reference), but pipegen adds none
  if (exprs(file.content) > exprs(original)) return ['the Dependabot file gains a ${{ expression, which is never part of pipegen\'s entry'];

  const out: string[] = [];
  const orig = original === '' ? ({ version: 2 } as Obj) : load(original, 'the existing Dependabot file', out);
  const next = load(file.content, 'the new Dependabot file', out);
  if (orig === null || next === null) return out;

  let expected;
  try { expected = dependabotEntry(draft) as unknown as Obj; } catch (e) { return [`the entry can not be built: ${e instanceof Error ? e.message : 'unknown error'}`]; }

  const before = orig.updates === undefined || orig.updates === null ? [] : orig.updates;
  if (!Array.isArray(before)) return ['the existing Dependabot file has an `updates` that is not a list'];
  // a github-actions entry for `/` already: pipegen adds nothing and never edits the user's entry
  for (const u of before) {
    if (isObj(u) && u['package-ecosystem'] === 'github-actions' && coversRoot(u)) {
      return ['the repository already has a github-actions entry for /; Dependabot rejects a duplicate and then stops all updates, so pipegen adds nothing and leaves the user\'s entry alone'];
    }
  }

  if (next.version !== 2 || orig.version !== 2) out.push('`version` must be 2');
  const after = next.updates;
  if (!Array.isArray(after)) return [...out, 'the new file has no `updates` list'];
  const keys = (o: Obj) => Object.keys(o).filter((k) => k !== 'updates').sort();
  if (!isDeepStrictEqual(keys(orig), keys(next))) out.push('the top-level keys differ from the user\'s file: pipegen only appends an entry');
  for (const k of keys(orig)) if (!isDeepStrictEqual(orig[k], next[k])) out.push(`the user's \`${k}\` was changed`);
  if (after.length !== before.length + 1) out.push(`exactly one entry must be appended (the file had ${before.length}, it now has ${after.length})`);
  if (after.length >= before.length && !isDeepStrictEqual(after.slice(0, before.length), before)) out.push('the user\'s existing entries were changed, removed or reordered');
  const added = after[before.length];
  if (added === undefined || after.length !== before.length + 1) return out;
  if (!isObj(added)) return [...out, 'the appended entry is not a map'];
  for (const k of Object.keys(added)) {
    if (!(k in expected)) out.push(`pipegen's entry sets \`${k}\`${WHY[k] === undefined ? '' : ` (${WHY[k]})`}, which pipegen never sets`);
  }
  if (!isDeepStrictEqual(added, expected)) out.push('the appended entry is not the one pipegen builds (github-actions, /, weekly, 7-day cooldown, grouped minor and patch updates)');
  return out;
}
