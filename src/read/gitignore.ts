// Plan J sub-task J1 (DECISIONS #126, ruling S11): which repo paths git ignores, read in-process, never by running git.
// Sources, lowest precedence first: .git/info/exclude (only when .git is a real folder), then every .gitignore file,
// shallowest first. Never core.excludesFile or a global ignore file: those are outside the repo and differ per machine.
//
// Every .gitignore is attacker-controlled. Files are read through readTextLimitedWithReason (1 MB, no symbolic link at
// any level, regular files only). At most 1,000 files and 10,000 patterns are used (ruling S11). The `ignore` package
// turns each pattern into a backtracking regular expression, which S11's limits alone don't keep safe (measured on
// ignore 7.0.14, J1 report), so, stricter than S11: a rule with more than one `**` (a trailing `/**` aside;
// `a/**/a/**/b` runs for minutes on a deep path) is not used as written, nor one over 1,000 characters or one the
// package can't compile; all rules together stay under 500,000 characters (10,000 long patterns exhaust memory); and
// matching has a work budget (rules × characters tested, counted the way the package caches folders). The budget is a
// count, not a clock, so two runs over the same files give the same answers (the counting and the checked AI bundles
// must match).
//
// Fix round 1 (review J1, I1): whenever one of those limits means pipegen can't tell what git would answer, the
// CALLER's safe side is used, given as `whenUnsure`:
//   - 'ignored' (the AI bundle: an ignored file must never be sent): a rule with several `**` is replaced by a broader
//     one with a single `**` (`X/**/Y/**/Z` → `X/**/Z`, which matches every path the original matches); any other
//     rule that can't be used, an unreadable .gitignore, or the files and patterns past a limit make every path under
//     that .gitignore's folder count as ignored; past the work budget every later path counts as ignored. A negation
//     (`!x`) that can't be used is simply dropped: that only makes more files ignored.
//   - 'not-ignored' (the quick secret check: a file must not be skipped unless git surely ignores it): the mirror
//     image. A negation with several `**` becomes a broader negation; any other negation that can't be used, an
//     unreadable .gitignore, or what lies past a limit make the paths under that folder count as not ignored; past
//     the budget every later path is not ignored; a positive rule that can't be used is dropped.
// A .gitignore that is a symbolic link adds nothing in either case: git itself doesn't follow one.
// Each case leaves one plain-English note in the matcher.
//
// All rules go into ONE matcher, each nested pattern rewritten to the path from the repo root (`*.gen.ts` in
// src/.gitignore becomes `src/**/*.gen.ts`, `/local` becomes `src/local`). Deeper files come later, so the last rule
// that matches decides, which is git's order (a deeper .gitignore beats a shallower one, a later line an earlier one),
// and the package's "a file under an excluded folder is excluded" check sees every file's rules at once, as git does.
// Matching is case-sensitive unless .git/config sets `ignorecase = true` (git's own switch).
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import ignore from 'ignore';
import { IGNORED_DIRS, listFiles, readTextLimitedWithReason, regexLines } from './limits.js';

export const IGNORE_LIMITS = Object.freeze({ maxFiles: 1000, maxPatterns: 10_000, maxPatternChars: 1000 });

/** J1's stricter guards on top of IGNORE_LIMITS (see the file comment): total pattern characters, `**` per rule, matching work. */
export const IGNORE_GUARDS = Object.freeze({ maxTotalChars: 500_000, maxDoubleStars: 1, maxMatchWork: 2_000_000_000 });

/** Which answer is safe for the caller when pipegen can't tell what git would say (see the file comment). */
export type WhenUnsure = 'ignored' | 'not-ignored';

export interface LoadIgnoreOptions {
  whenUnsure: WhenUnsure;
  /** Tests only: smaller guards. */
  guards?: { maxTotalChars?: number; maxDoubleStars?: number; maxMatchWork?: number };
}

/** Answers "does git ignore this path?" for repo-relative paths (forward slashes). */
export interface IgnoreMatcher {
  /**
   * True when the repo's ignore rules match `relPath` or a folder above it; where a limit leaves it unsure, the
   * caller's `whenUnsure` answer. A path the matcher can't take (empty, absolute, `..`) is false.
   */
  ignored(relPath: string): boolean;
  /** Plain-English notes on rules not used as written or matching stopped; read it after the last ignored() call (the budget note comes then). */
  readonly notes: readonly string[];
}

const treated = (u: WhenUnsure) => (u === 'ignored' ? 'treated as ignored' : 'treated as not ignored');

export const ignoreLimitNote = (u: WhenUnsure): string =>
  `pipegen read only the first ${IGNORE_LIMITS.maxFiles.toLocaleString('en-US')} .gitignore files and ${IGNORE_LIMITS.maxPatterns.toLocaleString('en-US')} patterns (${IGNORE_GUARDS.maxTotalChars.toLocaleString('en-US')} characters); files under the folders of the rest were ${treated(u)}.`;

export const ignoreSkippedNote = (n: number, u: WhenUnsure): string =>
  `pipegen couldn't use ${n === 1 ? '1 .gitignore pattern' : `${n.toLocaleString('en-US')} .gitignore patterns`} as written (too long, too complex to match safely, or not valid); files ${n === 1 ? 'it' : 'they'} could match were ${treated(u)}.`;

export const ignoreUnreadableNote = (n: number, u: WhenUnsure): string =>
  `pipegen couldn't read ${n === 1 ? '1 git ignore file' : `${n.toLocaleString('en-US')} git ignore files`} (larger than 1 MB, binary, or unreadable); files under ${n === 1 ? 'its folder' : 'their folders'} were ${treated(u)}.`;

export const ignoreBudgetNote = (u: WhenUnsure): string =>
  `pipegen stopped matching .gitignore rules part way (too many rules for too many files); the remaining files were ${treated(u)}.`;

/** The ignore rules of the checkout at `dir`. Never throws. */
export async function loadIgnore(dir: string, opts: LoadIgnoreOptions): Promise<IgnoreMatcher> {
  const unsure = opts.whenUnsure === 'ignored';
  const { maxTotalChars, maxDoubleStars, maxMatchWork } = { ...IGNORE_GUARDS, ...opts.guards };
  const git = await lstat(join(dir, '.git')).catch(() => null);
  const realGit = git !== null && !git.isSymbolicLink() && git.isDirectory();
  const ig = ignore({ ignorecase: realGit && (await ignoreCase(dir)) });
  /** Folders ('' = the whole repo) where every path gets the caller's unsure answer. */
  const zones = new Set<string>();
  let patterns = 0;
  let rules = 0;
  let chars = 0;
  let skipped = 0;
  let unreadable = 0;
  let pastLimit = false;
  /** Adds one file's rules; false when a limit stopped it (the rest of it is a zone). */
  const addFile = (text: string, base: string): boolean => {
    // git skips a UTF-8 byte order mark at the start of the file (review J1, I2)
    for (const raw of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
      const line = trimEnd(raw);
      if (line === '' || line.startsWith('#')) continue;
      if (patterns >= IGNORE_LIMITS.maxPatterns) return false;
      patterns++;
      // a rule whose loss would make the caller's answer wrong in the unsafe direction
      const mustKeep = unsure ? !line.startsWith('!') : line.startsWith('!');
      let rule = line.length > IGNORE_LIMITS.maxPatternChars ? undefined : scoped(line, base);
      if (rule === null) continue; // nothing left of it: it matches nothing, in git too
      if (rule !== undefined && doubleStars(rule) > maxDoubleStars) {
        skipped++;
        rule = mustKeep ? (broader(rule) ?? undefined) : null;
        if (rule === null) continue;
      }
      if (rule !== undefined && chars + rule.length > maxTotalChars) return false;
      if (rule === undefined || !compiles(rule)) {
        if (rule !== undefined || line.length > IGNORE_LIMITS.maxPatternChars) skipped++;
        if (mustKeep) zones.add(base);
        continue;
      }
      ig.add(rule);
      rules++;
      chars += rule.length;
    }
    return true;
  };
  /** A file whose rules are unknown: its folder is a zone. */
  const unknown = (base: string) => zones.add(base);

  if (realGit) {
    const path = join(dir, '.git/info/exclude');
    if ((await lstat(path).catch(() => null)) !== null) {
      const exclude = await readTextLimitedWithReason(path, dir);
      if (!('text' in exclude)) {
        unreadable++;
        unknown('');
      } else if (!addFile(exclude.text, '')) {
        pastLimit = true;
        unknown('');
      }
    }
  }

  const listing = await listFiles(dir, ['**/.gitignore'], IGNORED_DIRS.map((d) => `**/${d}/**`));
  const files = listing.files.filter((f) => f === '.gitignore' || f.endsWith('/.gitignore')).sort(byDepthThenPath);
  // a listing cut at the file limit may have missed .gitignore files anywhere
  if (listing.truncated) {
    pastLimit = true;
    unknown('');
  }
  for (let i = 0; i < files.length; i++) {
    const file = files[i] as string;
    const base = file.slice(0, -'.gitignore'.length).replace(/\/$/, '');
    if (pastLimit || i >= IGNORE_LIMITS.maxFiles) {
      pastLimit = true;
      unknown(base);
      continue;
    }
    const read = await readTextLimitedWithReason(join(dir, file), dir);
    if (!('text' in read)) {
      // git doesn't follow a .gitignore that is a symbolic link either: no rules, nothing unsure
      if (read.skipped !== 'link') {
        unreadable++;
        unknown(base);
      }
      continue;
    }
    if (!addFile(read.text, base)) {
      pastLimit = true;
      unknown(base);
    }
  }

  const notes: string[] = [];
  if (pastLimit) notes.push(ignoreLimitNote(opts.whenUnsure));
  if (skipped > 0) notes.push(ignoreSkippedNote(skipped, opts.whenUnsure));
  if (unreadable > 0) notes.push(ignoreUnreadableNote(unreadable, opts.whenUnsure));
  const inZone = (relPath: string): boolean => {
    if (zones.size === 0) return false;
    if (zones.has('')) return true;
    const parts = relPath.split('/');
    for (let i = 1; i < parts.length; i++) if (zones.has(parts.slice(0, i).join('/'))) return true;
    return false;
  };
  // the work budget: the package tests every rule on the path and on each folder above it it hasn't tested yet
  const tested = new Set<string>();
  let work = 0;
  let stopped = false;
  const levels = (relPath: string): string[] => {
    const keys: string[] = [];
    const parts = relPath.split('/');
    for (let i = parts.length; i >= 1; i--) {
      const key = i === parts.length ? relPath : `${parts.slice(0, i).join('/')}/`;
      if (tested.has(key)) break;
      keys.push(key);
    }
    return keys;
  };
  return Object.freeze({
    ignored(relPath: string): boolean {
      if (typeof relPath !== 'string' || !ignore.isPathValid(relPath)) return false;
      if (inZone(relPath) || stopped) return unsure;
      if (rules === 0) return false;
      const keys = levels(relPath);
      work += keys.reduce((n, k) => n + k.length + 1, 0) * rules;
      if (work > maxMatchWork) {
        stopped = true;
        notes.push(ignoreBudgetNote(opts.whenUnsure));
        return unsure;
      }
      for (const k of keys) tested.add(k);
      try {
        return ig.ignores(relPath);
      } catch {
        return unsure;
      }
    },
    get notes(): readonly string[] {
      return [...notes];
    },
  });
}

/** git's core.ignorecase from .git/config (read loosely: any `ignorecase` key set to a true value). Unreadable → false. */
async function ignoreCase(dir: string): Promise<boolean> {
  const r = await readTextLimitedWithReason(join(dir, '.git/config'), dir);
  if (!('text' in r)) return false;
  return regexLines(r.text).some((l) => /^\s*ignorecase\s*=\s*(?:true|yes|on|1)\s*(?:[;#].*)?$/i.test(l));
}

/** The `**` in a rule, a trailing `/**` not counted (it only says "everything under"). */
function doubleStars(rule: string): number {
  return (rule.replace(/\/\*\*$/, '').match(/\*\*/g) ?? []).length;
}

// A rule with one `**` that matches every path `rule` matches: the text before the first `**` and after the last one,
// joined by one `**` (`a/**/b/**/c` becomes `a/**/c`). Only when both joins are folder boundaries (so the `**` stands
// for whole folders, as in the original); else null. A trailing `/**` and a leading `!` are kept.
function broader(rule: string): string | null {
  const neg = rule.startsWith('!') ? '!' : '';
  let body = neg === '' ? rule : rule.slice(1);
  const tail = body.endsWith('/**') ? '/**' : '';
  if (tail !== '') body = body.slice(0, -3);
  const first = body.indexOf('**');
  const last = body.lastIndexOf('**');
  if (first === -1 || first === last) return null;
  const head = body.slice(0, first);
  const end = body.slice(last + 2);
  if (!(head === '' || head.endsWith('/')) || !(end === '' || end.startsWith('/'))) return null;
  return `${neg}${head}**${end}${tail}`;
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
