// The CODEOWNERS judge (v0.2 Plan D, D0b; preflight 4.2 and S14). Plan G writes the file; the referee holds it to this:
//  - the PATH is the one GitHub (and the gate, integrity.ts loadCodeowners) reads: the first of .github/CODEOWNERS, CODEOWNERS,
//    docs/CODEOWNERS that exists, else .github/CODEOWNERS. A block in a lower-priority file is silently ignored; a new higher one hides the user's;
//  - the EDIT FORM is the user's original text as a byte prefix, then exactly one block, built by codeownersBlock();
//  - the OWNERS are the draft's (user logins, never a team, e-mail or bot), at least two when two or more users can write (S14: one owner
//    can not approve their own pull request, so a sole owner would lock every protected-path change);
//  - the SEMANTICS are checked with the gate's own parser: every protected path, on a probe list, is owned by exactly the owners.
import picomatch from 'picomatch';
import { codeOwners, MAX_CODEOWNERS_BYTES, ownersOf } from '../../../gate/src/integrity.js';
import { CENTRAL_PROTECTED_PATHS, CODEOWNERS_BEGIN, CODEOWNERS_END, codeownersBlock, codeownersFile, codeownersOwnerProblem, codeownersProtectedPaths, codeownersReplace } from '../created-builders.js';
import type { CreatedCtx } from '../created-files.js';
import type { CreatedFile } from '../../types.js';

const CO_PLACES: readonly string[] = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
const MARKER_RE = /pipegen:(?:begin|end)/;
const NO_ROOT = (r: string): boolean => r !== '' && r !== '.';

const normRoot = (r: string): string => r.replace(/^(?:\.\/)+|\/+$/g, '');
/** A glob made concrete: `**` a nested path, `*` and `?` one character. */
const concrete = (s: string): string => s.replace(/\*\*/g, 'a/b').replace(/[*?]+/g, 'x');

/**
 * Real paths that each protected path must cover: `dir/**` gets a child and a deep file; a name without a slash (any depth for the gate)
 * gets the root, a nested folder and each service root; `/name` the root file; `**\/name` the root and a nested folder; any other path itself.
 */
export function codeownersProbes(protectedPaths: readonly string[], serviceRoots: readonly string[]): string[] {
  const roots = [...new Set(serviceRoots.map(normRoot).filter(NO_ROOT))];
  const out = new Set<string>();
  for (const p of protectedPaths) {
    if (p.endsWith('/**')) {
      const dir = concrete(p.slice(0, -3).replace(/^\//, ''));
      out.add(`${dir}/x`); out.add(`${dir}/a/b/c.y`);
    } else if (p.startsWith('/')) out.add(concrete(p.slice(1)));
    else if (p.startsWith('**/')) { const r = concrete(p.slice(3)); out.add(r); out.add(`sub/dir/${r}`); }
    else if (!p.includes('/')) { const c = concrete(p); out.add(c); out.add(`sub/dir/${c}`); for (const r of roots) out.add(`${r}/${c}`); }
    else out.add(concrete(p));
  }
  return [...out];
}

/** The gate's matching of a protected path (integrity.ts pathMatcher): a name without a slash at any depth, a leading `/` the root only, case-insensitive. */
const protectedMatcher = (paths: readonly string[]): ((p: string) => boolean) => {
  const m = picomatch(paths.map((p) => (p.startsWith('/') ? p.slice(1) : p.includes('/') ? p : `**/${p}`)), { nocase: true, dot: true });
  return (p) => paths.length > 0 && m(p);
};

/**
 * Concrete paths for a rule pattern, lined up with each protected directory or path: a wildcard segment of the rule takes the protected path's
 * literal segment at the same position when it matches it (`work*` against `.github/workflows/**` gives `.github/workflows`), and `**` takes the
 * rest of the protected directory. So `/.github/work*\/deploy.yml` and `/.github/**\/deploy.yml` are tried on `.github/workflows/deploy.yml`.
 */
function alignedCandidates(pattern: string, protectedPaths: readonly string[]): string[] {
  const dirOnly = pattern.endsWith('/');
  const body = dirOnly ? pattern.slice(0, -1) : pattern;
  const anchored = body.startsWith('/') || body.includes('/');
  const rule = body.replace(/^\//, '').split('/');
  if (!anchored && /[*?]/.test(body)) rule.unshift('**');   // a bare literal name is not lined up with a directory: it names a file nobody has
  const out: string[] = [];
  for (const pp of protectedPaths) {
    if (pp.startsWith('**/')) continue;
    const prot = pp.replace(/^\//, '').replace(/\/\*\*$/, '').split('/');
    if (prot.some((x) => x === '' || x === '**')) continue;
    const segs: string[] = [];
    let j = 0;
    for (const r of rule) {
      if (r === '**') { segs.push(...prot.slice(j)); j = prot.length; continue; }
      const lit = j < prot.length ? (prot[j] as string) : undefined;
      segs.push(/[*?]/.test(r) ? (lit !== undefined && picomatch.isMatch(lit, r, { dot: true, nocase: true }) ? lit : concrete(r)) : r);
      j++;
    }
    out.push(segs.join('/'), `${segs.join('/')}/x`);
  }
  return out;
}

/**
 * The user rules AFTER pipegen's block (`after` is the text following it) that own a protected path differently from the block's owners:
 * the last matching rule wins, so such a rule silently takes the path back. Each rule line is tried on the concrete paths its pattern names
 * (the pattern itself, something under it, and at depth for a slashless name); a path counts when the gate treats it as protected and the
 * owners it reads, with the block in front of the rule, are not exactly `owners`. Returns the rule lines (for the refusal and for Plan G's note).
 */
export function codeownersLaterOverrides(after: string, protectedPaths: readonly string[], owners: readonly string[]): string[] {
  if (after.trim() === '') return [];
  const isProtected = protectedMatcher(protectedPaths);
  const want = owners.map((o) => o.replace(/^@/, '').toLowerCase()).sort().join(',');
  const out: string[] = [];
  for (const line of after.split(/\r?\n/)) {
    const rules = codeOwners(line);
    if (rules.length === 0) continue;
    const pat = (rules[0] as { pattern: string }).pattern;
    const c = concrete(pat.replace(/^\//, '').replace(/\/$/, ''));
    const cands = [c, `${c}/x`, ...(pat.includes('/') ? [] : [`sub/dir/${c}`]), ...alignedCandidates(pat, protectedPaths)];
    const hit = cands.some((p) => isProtected(p) && (ownersOf(rules, p)?.slice().sort().join(',') ?? '\0') !== want);
    if (hit) out.push(line.trim());
  }
  return out;
}

/** Files that must stay unowned by the block (a rule that owns more than the protected set would capture review). */
const NEGATIVE_PROBES = ['src/index.ts', 'README.md', 'package.json', 'a/b/c.txt', 'workflows/ci.yml', 'github/workflows/x.yml', 'docs/guide.md'];

/**
 * Parse `text` with the gate's parser and check that every probe of every protected path is owned by exactly `owners` (the last matching
 * rule wins, as on GitHub). With `negatives` (the block alone), a few ordinary files must have no owner at all.
 */
export function codeownersSemanticProblems(text: string, protectedPaths: readonly string[], serviceRoots: readonly string[], owners: readonly string[], negatives = true): string[] {
  const rules = codeOwners(text);
  const want = owners.map((o) => o.replace(/^@/, '').toLowerCase()).sort().join(',');
  const probes = codeownersProbes(protectedPaths, serviceRoots);
  const bad = probes.filter((p) => (ownersOf(rules, p)?.slice().sort().join(',') ?? '\0') !== want);
  const problems: string[] = [];
  if (bad.length > 0) problems.push(`the gate would not read ${bad.length} protected path${bad.length === 1 ? '' : 's'} as owned by exactly the code owners (for example ${bad.slice(0, 3).join(', ')}); a pattern is wrong, so a protected path would be unowned or owned by someone else`);
  if (negatives) {
    const extra = NEGATIVE_PROBES.filter((p) => !probes.includes(p) && ownersOf(rules, p) !== undefined);
    if (extra.length > 0) problems.push(`the block owns files that are not protected (for example ${extra.slice(0, 3).join(', ')}), which would capture their review`);
  }
  return problems;
}

/** The judge for one repo: the app repo's file owns the gate's protected paths, the central repo's the workflows and install records. */
function judge(repo: 'app' | 'central') {
  return (file: CreatedFile, ctx: CreatedCtx): string[] => {
    const { draft } = ctx;
    const out: string[] = [];
    const co = draft.codeOwners;
    if (co === undefined) return ['the draft has no code owners (the probe of who can approve was not made), so pipegen writes no CODEOWNERS'];
    const ownerBad = codeownersOwnerProblem(co.owners);
    if (ownerBad !== null) return [`${ownerBad}, so pipegen writes no CODEOWNERS`];
    if (typeof co.writers !== 'number' || !Number.isSafeInteger(co.writers) || co.writers < 0) return ['the count of users with write access is not a whole number, so pipegen writes no CODEOWNERS'];
    if (co.writers >= 2 && co.owners.length < 2) return [`${co.writers} users can write but there is one code owner: that owner could not approve their own pull request, so every protected-path change would be locked (add a second owner, or use the single-writer layout)`];


    const found = repo === 'app' ? draft.profile.repoFiles.codeowners : ctx.inputs.centralCodeowners;
    if (found === undefined) return ['the central repository\'s existing CODEOWNERS was not given to the referee, so the file path can not be checked'];
    if (found !== null && !CO_PLACES.includes(found)) return ['the existing CODEOWNERS path is not one GitHub reads'];
    const want = found ?? '.github/CODEOWNERS';
    if (file.path !== want) return [`GitHub reads the first CODEOWNERS file that exists (.github/CODEOWNERS, then CODEOWNERS, then docs/CODEOWNERS); here that is ${want}, so a block in ${file.path} would be ignored or would hide the existing file`];

    const original = file.edited?.original;
    if (typeof original !== 'string') return ['the edited marker with the original text is missing'];
    if (found === null && original !== '') return ['no CODEOWNERS file exists, but an original text was given'];
    let facts: { isSymlink: boolean; inserted: string | null } | undefined;
    if (found !== null) {
      facts = ctx.inputs.codeownersFacts?.[repo];
      if (facts === undefined) return ['whether the existing CODEOWNERS is a symbolic link, and the block the install record owns in it, was not given to the referee'];
      if (facts.isSymlink) return ['the existing CODEOWNERS is a symbolic link, which GitHub reads but pipegen will not write through'];
    }
    if (Buffer.byteLength(file.content, 'utf8') > MAX_CODEOWNERS_BYTES) return ['the CODEOWNERS file is over 3 MiB, which GitHub does not read'];

    const roots = repo === 'app' ? draft.profile.services.map((s) => s.path) : [];
    const paths = repo === 'app' ? codeownersProtectedPaths(draft, ctx.reviewed) : [...CENTRAL_PROTECTED_PATHS];
    let block: string;
    try { block = codeownersBlock(paths, co.owners); } catch (e) { return [`the block can not be built: ${e instanceof Error ? e.message : 'unknown error'}`]; }
    let expected: string;
    if (MARKER_RE.test(original)) {
      // a re-run: allowed only when the install record owns the old block, found exactly once and whole; it is replaced in place
      const ins = facts?.inserted;
      const replaced = typeof ins === 'string' && ins.startsWith(`${CODEOWNERS_BEGIN}\n`) && ins.endsWith(`${CODEOWNERS_END}\n`) ? codeownersReplace(original, ins, block) : null;
      if (typeof ins !== 'string' || replaced === null || MARKER_RE.test(original.replace(ins, ''))) return ['the original CODEOWNERS already holds a pipegen:begin or pipegen:end marker that the install record does not own as one whole block; a second block would be ambiguous'];
      expected = replaced;
      const at = expected.indexOf(block);
      if (at >= 0) {
        const later = codeownersLaterOverrides(expected.slice(at + block.length), paths, co.owners);
        if (later.length > 0) out.push(`${later.length} rule${later.length === 1 ? '' : 's'} after the pipegen block take${later.length === 1 ? 's' : ''} a protected path back from the code owners (${later.slice(0, 3).join(' | ')}); the last matching rule wins, so the block would not own it`);
      }
    } else expected = codeownersFile(original, block);
    if (file.content !== expected) {
      return [expected === codeownersFile(original, block) && !file.content.startsWith(original)
        ? 'the original text is not a byte prefix of the file: pipegen only appends its block and never changes the user\'s lines'
        : 'the file is not exactly the original plus the pipegen block (the protected paths with the code owners; on a re-run, the original with only the old block replaced), so it is refused'];
    }
    out.push(...codeownersSemanticProblems(block, paths, roots, co.owners));
    out.push(...codeownersSemanticProblems(file.content, paths, roots, co.owners, false));
    return out;
  };
}

export const codeownersJudge = judge('app');
export const codeownersCentralJudge = judge('central');
