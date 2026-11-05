// Plan J sub-task J1 (DECISIONS #126, ruling S11): which repo paths git ignores, read in-process, never by running git.
// Sources, lowest precedence first: .git/info/exclude (only when .git is a real folder), then every .gitignore file,
// shallowest first. Never core.excludesFile or a global ignore file: those are outside the repo and differ per machine.
//
// Every .gitignore is attacker-controlled. Files are read through readTextLimitedWithReason (1 MB, no symbolic link at
// any level, regular files only); an unreadable file adds no rules. At most 1,000 files and 10,000 patterns are used
// (ruling S11); past either limit the rest add no rules and the matcher carries one note. The `ignore` package turns
// each pattern into a backtracking regular expression, which ruling S11's limits alone don't keep safe (measured on
// ignore 7.0.14, J1 report): so, stricter than S11, a pattern adds nothing when it is over 1,000 characters, has more
// than one `**` (a trailing `/**` aside; `a/**/a/**/b` runs for minutes on a deep path), can't be compiled, or would
// take the patterns past 500,000 characters in all (10,000 long patterns exhaust memory). Those carry their own note.
// Matching has a work budget (rules × characters tested, counted the way the package caches folders), so a hostile
// mix of many rules and deep paths can only slow the audit by seconds; past it every later path counts as not
// ignored (the audit as it was before J1) and the matcher carries a note. The budget is a count, not a clock, so two
// runs over the same files give the same answers (the counting and the checked AI bundles must match).
//
// All rules go into ONE matcher, each nested pattern rewritten to the path from the repo root (`*.gen.ts` in
// src/.gitignore becomes `src/**/*.gen.ts`, `/local` becomes `src/local`). Deeper files come later, so the last rule
// that matches decides, which is git's order (a deeper .gitignore beats a shallower one, a later line an earlier one),
// and the package's "a file under an excluded folder is excluded" check sees every file's rules at once, as git does.
// Matching is case-sensitive, like git's default (core.ignorecase false) on the Linux runners CI uses.
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import ignore from 'ignore';
import { IGNORED_DIRS, listFiles, readTextLimitedWithReason } from './limits.js';

export const IGNORE_LIMITS = Object.freeze({ maxFiles: 1000, maxPatterns: 10_000, maxPatternChars: 1000 });

/** J1's stricter guards on top of IGNORE_LIMITS (see the file comment): total pattern characters, `**` per rule, matching work. */
export const IGNORE_GUARDS = Object.freeze({ maxTotalChars: 500_000, maxDoubleStars: 1, maxMatchWork: 2_000_000_000 });

/** Answers "does git ignore this path?" for repo-relative paths (forward slashes). */
export interface IgnoreMatcher {
  /** True when the repo's ignore rules match `relPath` or a folder above it. A path the matcher can't take (empty, absolute, `..`) is false. */
  ignored(relPath: string): boolean;
  /** Plain-English notes on rules left out or matching stopped; read it after the last ignored() call (the budget note comes then). */
  readonly notes: readonly string[];
}

export const IGNORE_LIMIT_NOTE = `pipegen read only the first ${IGNORE_LIMITS.maxFiles.toLocaleString('en-US')} .gitignore files and ${IGNORE_LIMITS.maxPatterns.toLocaleString('en-US')} patterns; the rest were not used, so some files git ignores were treated as not ignored.`;

/** The note for patterns left out one by one (too long, too complex, not valid, past the total size). */
export const ignoreSkippedNote = (n: number): string =>
  `pipegen didn't use ${n === 1 ? '1 .gitignore pattern' : `${n.toLocaleString('en-US')} .gitignore patterns`} (too long, too complex to match safely, or not valid); files only ${n === 1 ? 'it lists were' : 'they list were'} treated as not ignored.`;

export const IGNORE_BUDGET_NOTE = 'pipegen stopped matching .gitignore rules part way (too many rules for too many files); the remaining files were treated as not ignored.';

/** The ignore rules of the checkout at `dir`. Never throws: anything unreadable adds no rules. `guards` is for tests only. */
export async function loadIgnore(dir: string, guards: { maxTotalChars?: number; maxDoubleStars?: number; maxMatchWork?: number } = {}): Promise<IgnoreMatcher> {
  const { maxTotalChars, maxDoubleStars, maxMatchWork } = { ...IGNORE_GUARDS, ...guards };
  const ig = ignore({ ignorecase: false });
  let patterns = 0;
  let rules = 0;
  let chars = 0;
  let skipped = 0;
  let tooManyPatterns = false;
  const addFile = (text: string, base: string): void => {
    for (const raw of text.split(/\r?\n/)) {
      if (tooManyPatterns) return;
      const line = trimEnd(raw);
      if (line === '' || line.startsWith('#')) continue;
      if (patterns >= IGNORE_LIMITS.maxPatterns) {
        tooManyPatterns = true;
        return;
      }
      patterns++;
      const rule = line.length > IGNORE_LIMITS.maxPatternChars ? null : scoped(line, base);
      if (rule === null || doubleStars(rule) > maxDoubleStars || chars + rule.length > maxTotalChars || !compiles(rule)) {
        skipped++;
        continue;
      }
      ig.add(rule);
      rules++;
      chars += rule.length;
    }
  };

  const git = await lstat(join(dir, '.git')).catch(() => null);
  if (git !== null && !git.isSymbolicLink() && git.isDirectory()) {
    const exclude = await readTextLimitedWithReason(join(dir, '.git/info/exclude'), dir);
    if ('text' in exclude) addFile(exclude.text, '');
  }

  const listing = await listFiles(dir, ['**/.gitignore'], IGNORED_DIRS.map((d) => `**/${d}/**`));
  const files = listing.files.filter((f) => f === '.gitignore' || f.endsWith('/.gitignore')).sort(byDepthThenPath);
  const tooManyFiles = files.length > IGNORE_LIMITS.maxFiles || listing.truncated;
  for (const file of files.slice(0, IGNORE_LIMITS.maxFiles)) {
    if (tooManyPatterns) break;
    const read = await readTextLimitedWithReason(join(dir, file), dir);
    if ('text' in read) addFile(read.text, file.slice(0, -'.gitignore'.length).replace(/\/$/, ''));
  }

  const notes: string[] = [];
  if (tooManyFiles || tooManyPatterns) notes.push(IGNORE_LIMIT_NOTE);
  if (skipped > 0) notes.push(ignoreSkippedNote(skipped));
  // the work budget: the package tests every rule on the path and on each folder above it it hasn't tested yet
  const tested = new Set<string>();
  let work = 0;
  let stopped = false;
  const cost = (relPath: string): number => {
    let total = 0;
    const parts = relPath.split('/');
    for (let i = parts.length; i >= 1; i--) {
      const key = i === parts.length ? relPath : `${parts.slice(0, i).join('/')}/`;
      if (tested.has(key)) break;
      total += key.length + 1;
    }
    return total * Math.max(rules, 1);
  };
  const remember = (relPath: string): void => {
    const parts = relPath.split('/');
    for (let i = parts.length; i >= 1; i--) {
      const key = i === parts.length ? relPath : `${parts.slice(0, i).join('/')}/`;
      if (tested.has(key)) break;
      tested.add(key);
    }
  };
  return Object.freeze({
    ignored(relPath: string): boolean {
      if (rules === 0 || stopped) return false;
      if (typeof relPath !== 'string' || !ignore.isPathValid(relPath)) return false;
      work += cost(relPath);
      if (work > maxMatchWork) {
        stopped = true;
        notes.push(IGNORE_BUDGET_NOTE);
        return false;
      }
      remember(relPath);
      try {
        return ig.ignores(relPath);
      } catch {
        return false;
      }
    },
    get notes(): readonly string[] {
      return [...notes];
    },
  });
}

/** The `**` in a rule, a trailing `/**` not counted (it only says "everything under"). */
function doubleStars(rule: string): number {
  return (rule.replace(/\/\*\*$/, '').match(/\*\*/g) ?? []).length;
}

const depth = (p: string) => p.split('/').length;
const byDepthThenPath = (a: string, b: string) => depth(a) - depth(b) || (a < b ? -1 : a > b ? 1 : 0);

/** True when the package can build this rule's regular expression (it builds them lazily, on the first match). */
function compiles(rule: string): boolean {
  try {
    const probe = ignore({ ignorecase: false }).add(rule);
    probe.ignores('a');
    probe.ignores('a/b');
    return true;
  } catch {
    return false;
  }
}

/**
 * git's trailing-space rule: unescaped trailing spaces are dropped; an escaped one (`\ `) stays as a space. Done before
 * the rewrite so `out/   ` is still a folder rule.
 */
function trimEnd(line: string): string {
  let end = line.length;
  while (end > 0 && line[end - 1] === ' ') end--;
  if (end === line.length) return line;
  let slashes = 0;
  while (slashes < end && line[end - slashes - 1] === '\\') slashes++;
  return slashes % 2 === 1 ? `${line.slice(0, end)} ` : line.slice(0, end);
}

/** `base` (a folder path) as literal pattern text: glob characters escaped, and a leading `!` or `#`. */
function literal(base: string): string {
  return base.replace(/[\\*?[\]]/g, (c) => `\\${c}`).replace(/^[!#]/, (c) => `\\${c}`);
}

/**
 * `line` from the .gitignore in folder `base` ('' for the root and info/exclude) as a rule on root-relative paths, or
 * null when nothing is left of it. git: a pattern with a slash at its start or middle is relative to its file's folder;
 * one without (a trailing slash aside) matches at any depth below it.
 */
function scoped(line: string, base: string): string | null {
  if (base === '') return line;
  const negated = line.startsWith('!');
  const body = negated ? line.slice(1) : line;
  const core = body.endsWith('/') ? body.slice(0, -1) : body;
  if (core === '' || core === '/') return null;
  const anchored = core.includes('/');
  const rest = anchored ? body.replace(/^\/+/, '') : `**/${body}`;
  if (rest === '' || rest === '/') return null;
  return `${negated ? '!' : ''}${literal(base)}/${rest}`;
}
