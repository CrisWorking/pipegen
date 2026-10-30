// The pure builders for the files Plan G writes and the D0b judges re-check (v0.2 Plan D, D0b; preflight 4.2). Plan G calls these to
// produce a CODEOWNERS block and a dependabot entry; the judges call the same functions and compare byte for byte (or value for value),
// so the producer and the referee can not drift. A leaf: types, the protected-path leaf and the gate's LOGIN_RE only.
import { LOGIN_RE, MAX_LINE } from '../../gate/src/integrity.js';
import type { PipelineDraft, ReviewedTool } from '../types.js';
import { effectiveProtectedPaths } from './protected-paths.js';

// ---------- CODEOWNERS ----------

export const CODEOWNERS_BEGIN = '# pipegen:begin';
export const CODEOWNERS_END = '# pipegen:end';
/** The central repo's CODEOWNERS covers the workflows (project files) and the install records. */
export const CENTRAL_PROTECTED_PATHS: readonly string[] = Object.freeze(['.github/workflows/**', 'installs/**']);

const PATH_CHARS = /^[A-Za-z0-9._*?/-]+$/;
const wild = (seg: string): boolean => /^[*?]+$/.test(seg);

/**
 * A protected path (the gate's form) as a CODEOWNERS pattern, with the anchoring the gate reads it with:
 * `dir/**` -> `/dir/` (the whole subtree), a name without a slash -> itself (any depth), `/name` -> `/name` (root only),
 * `**\/name` -> itself, any other path with a slash -> anchored with a leading slash. Throws for a path the format can not carry
 * (a space, `#`, `!`, brackets, a backslash, `..`, an empty or all-wildcard path): such a line would be dropped or would own too much.
 */
export function codeownersPattern(path: string): string {
  if (typeof path !== 'string' || path === '' || !PATH_CHARS.test(path)) throw new Error(`the protected path ${JSON.stringify(String(path).slice(0, 60))} can not be written as a CODEOWNERS pattern`);
  if (path.includes('//') || path.endsWith('/') && !path.endsWith('/**')) throw new Error(`the protected path ${JSON.stringify(path.slice(0, 60))} is not a plain path`);
  const segs = path.replace(/^\//, '').split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) throw new Error(`the protected path ${JSON.stringify(path.slice(0, 60))} is not a plain path`);
  if (path.endsWith('/**')) {
    const dir = path.slice(0, -3);
    if (dir === '' || dir.split('/').every((s) => s === '' || wild(s))) throw new Error(`the protected path ${JSON.stringify(path)} would own the whole repository`);
    return dir.startsWith('**/') ? `${dir}/` : `/${dir.replace(/^\//, '')}/`;
  }
  if (wild(segs[segs.length - 1] as string)) throw new Error(`the protected path ${JSON.stringify(path.slice(0, 60))} would own a whole folder`);
  if (path.startsWith('**/') || path.startsWith('/')) return path;
  return path.includes('/') ? `/${path}` : path;
}

/** The owners as the gate reads them: `@login` only (no team, e-mail or bot), at least one, none twice (ignoring case). */
export function codeownersOwnerProblem(owners: unknown): string | null {
  if (!Array.isArray(owners) || owners.length === 0) return 'the list of code owners is empty';
  const seen = new Set<string>();
  for (const o of owners) {
    if (typeof o !== 'string' || !LOGIN_RE.test(o)) return 'a code owner is not a user login (@name): a team, an e-mail address, a bot or a bare name is not accepted';
    if (seen.has(o.toLowerCase())) return 'a code owner is listed twice';
    seen.add(o.toLowerCase());
  }
  return null;
}

/**
 * The block between `# pipegen:begin` and `# pipegen:end`: one line per pattern, every line with the same owners. Throws on an owner or a
 * path the format can not carry, and on a line over the gate's 4096-character limit (the gate would skip it).
 */
export function codeownersBlock(paths: readonly string[], owners: readonly string[]): string {
  const bad = codeownersOwnerProblem(owners);
  if (bad !== null) throw new Error(bad);
  if (paths.length === 0) throw new Error('there is no path to protect');
  const patterns = [...new Set(paths.map(codeownersPattern))];
  const lines = patterns.map((p) => `${p} ${owners.join(' ')}`);
  if (lines.some((l) => l.length > MAX_LINE)) throw new Error(`a CODEOWNERS line is over ${MAX_LINE} characters, so the gate would skip it`);
  return `${CODEOWNERS_BEGIN}\n${lines.join('\n')}\n${CODEOWNERS_END}\n`;
}

/** The new file: the original, a blank line when it has text, then the block. The original stays a byte prefix. */
export function codeownersFile(original: string, block: string): string {
  if (original === '') return block;
  return `${original}${original.endsWith('\n') ? '\n' : '\n\n'}${block}`;
}

/**
 * The paths the app repo's block owns: what the gate protects (effectiveProtectedPaths over the whole reviewed list and the service
 * roots, plus the `protected-paths` the draft records). A protected path nobody owns can not be approved by anybody, so the block must
 * cover all of them, not only the tools in use.
 */
export function codeownersProtectedPaths(draft: PipelineDraft, reviewed: readonly Pick<ReviewedTool, 'configFiles' | 'rootConfigFiles'>[]): string[] {
  const roots = draft.profile.services.map((s) => s.path);
  return [...new Set([...effectiveProtectedPaths(reviewed, roots), ...(draft.gateSettings?.protectedPaths ?? [])])];
}

// ---------- dependabot ----------

export interface DependabotEntry {
  'package-ecosystem': 'github-actions';
  directory: '/';
  schedule: { interval: 'weekly' };
  cooldown: { 'default-days': 7 };
  groups: { 'github-actions-minor-patch': { 'update-types': ['minor', 'patch']; patterns: ['*'] } };
  ignore?: { 'dependency-name': string }[];
}

const CENTRAL_REPO_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?!\.+$)[A-Za-z0-9._-]{1,100}$/;

/**
 * The one `github-actions` entry pipegen appends to dependabot.yml: weekly, a 7-day cooldown, minor and patch updates in one group
 * (a major update, having no group, is its own pull request; Dependabot has no group type for digests, and a pinned action's new commit
 * is a version change, so it lands in these groups). A private repository ignores the central repo (`<owner>/<central>/*`, DECISIONS #89),
 * since Dependabot can not read it. Throws for a private repository with no valid central pin.
 */
export function dependabotEntry(draft: PipelineDraft): DependabotEntry {
  const entry: DependabotEntry = {
    'package-ecosystem': 'github-actions', directory: '/', schedule: { interval: 'weekly' }, cooldown: { 'default-days': 7 },
    groups: { 'github-actions-minor-patch': { 'update-types': ['minor', 'patch'], patterns: ['*'] } },
  };
  if (draft.profile.private) {
    const repo = draft.centralPin?.repo;
    if (typeof repo !== 'string' || !CENTRAL_REPO_RE.test(repo)) throw new Error('a private repository needs the central repository (owner/name) to ignore in Dependabot');
    entry.ignore = [{ 'dependency-name': `${repo}/*` }];
  }
  return entry;
}
