// The pure builders for the files Plan G writes and the D0b judges re-check (v0.2 Plan D, D0b; preflight 4.2). Plan G calls these to
// produce a CODEOWNERS block and a dependabot entry; the judges call the same functions and compare byte for byte (or value for value),
// so the producer and the referee can not drift. A leaf: types, the protected-path leaf and the gate's LOGIN_RE only.
import { LOGIN_RE, MAX_LINE } from '../../gate/src/integrity.js';
import type { PipelineDraft, ReviewedTool } from '../types.js';
import { effectiveProtectedPaths } from './protected-paths.js';
import { isObj, parseYaml } from './yaml-parse.js';

// ---------- CODEOWNERS ----------

export const CODEOWNERS_BEGIN = '# pipegen:begin';
export const CODEOWNERS_END = '# pipegen:end';
/**
 * The central repo's CODEOWNERS covers the workflows (project files), the install records and the CODEOWNERS files themselves (D0b fix round 1,
 * review finding 3): otherwise any writer could re-own the workflows in one pull request and change them in the next.
 */
export const CENTRAL_PROTECTED_PATHS: readonly string[] = Object.freeze(['.github/workflows/**', 'installs/**', '.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']);

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
 * The second edit form (a re-run): `inserted` is the old block the install record says pipegen wrote (EditKind 'codeowners'); it is replaced
 * in place by the new block and every other byte stays. Returns null if `inserted` is not in the original exactly once.
 */
export function codeownersReplace(original: string, inserted: string, block: string): string | null {
  const i = inserted === '' ? -1 : original.indexOf(inserted);
  if (i < 0 || original.indexOf(inserted, i + 1) >= 0) return null;
  return `${original.slice(0, i)}${block}${original.slice(i + inserted.length)}`;
}

/** The user's rules (outside pipegen's own old block) whose pattern is also a line of `block`: the block overrides them, so a note should list them. */
export function codeownersOverrides(original: string, block: string): string[] {
  const own = (t: string): string | undefined => t.trim().split(/\s+/)[0];
  const patterns = new Set(block.split('\n').filter((l) => l.trim() !== '' && !l.startsWith('#')).map(own));
  const user = original.replace(new RegExp(`${CODEOWNERS_BEGIN}\\n[\\s\\S]*?${CODEOWNERS_END}\\n?`, 'g'), '');
  return user.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#') && patterns.has(own(l)));
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

/** The entry as text, every string quoted so YAML 1.1 (Dependabot's Ruby reader) and 1.2 read it alike; `default-days` is a plain integer. */
export function dependabotEntryText(draft: PipelineDraft): string {
  const e = dependabotEntry(draft);
  const q = JSON.stringify;
  const lines = [
    `  - package-ecosystem: ${q(e['package-ecosystem'])}`, `    directory: ${q(e.directory)}`, '    schedule:', `      interval: ${q(e.schedule.interval)}`,
    '    cooldown:', `      default-days: ${e.cooldown['default-days']}`, '    groups:', '      github-actions-minor-patch:',
    `        update-types: [${e.groups['github-actions-minor-patch']['update-types'].map((t) => q(t)).join(', ')}]`, `        patterns: [${e.groups['github-actions-minor-patch'].patterns.map((t) => q(t)).join(', ')}]`,
  ];
  if (e.ignore !== undefined) lines.push('    ignore:', ...e.ignore.map((i) => `      - dependency-name: ${q(i['dependency-name'])}`));
  return `${lines.join('\n')}\n`;
}

/**
 * The whole dependabot.yml: the user's bytes untouched, then pipegen's entry TEXT appended (never a re-stringified file: yaml.stringify writes
 * `no` and `on` unquoted, which Dependabot's YAML 1.1 reader turns into booleans, and comments would be lost). Only one shape is supported:
 * `updates:` is the last top-level key (or absent) and its items are a block sequence at the standard two-space indentation. Any other shape,
 * a file that already has a github-actions entry (whatever its directory or branch), or a file that does not parse strictly gives no file and
 * a note with the exact entry to add by hand. Throws like dependabotEntry (a private repo without a central pin).
 */
export function dependabotFile(original: string, draft: PipelineDraft): { content: string } | { note: string } {
  const entry = dependabotEntryText(draft);
  if (original === '') return { content: `version: 2\nupdates:\n${entry}` };
  const by = (why: string): { note: string } => ({ note: `pipegen can not add its Dependabot entry to this file safely (${why}); add this entry by hand under \`updates:\` in the Dependabot file:\n${entry}` });
  if (/[\r\t]/.test(original)) return by('it uses CRLF line ends or tabs');
  const r = parseYaml(original, 'strict');
  if ('problems' in r) return by(`it does not parse strictly: ${r.problems.join('; ')}`);
  const js = r.parsed.js;
  const upd = js.updates;
  if (Array.isArray(upd) && upd.some((u) => isObj(u) && u['package-ecosystem'] === 'github-actions')) return { note: 'the repository already has a github-actions entry in its Dependabot file; pipegen adds nothing and leaves it alone' };
  const nl = original.endsWith('\n') ? original : `${original}\n`;
  if (!('updates' in js)) return { content: `${nl}updates:\n${entry}` };
  const keys = Object.keys(js);
  if (keys[keys.length - 1] !== 'updates') return by('`updates` is not the last top-level key');
  const lines = original.split('\n');
  const at = lines.map((l, i) => (/^updates:[ \t]*(?:#.*)?$/.test(l) ? i : -1)).filter((i) => i >= 0);
  if (at.length !== 1) return by('`updates:` is not written as a plain key line');
  const body = lines.slice((at[0] as number) + 1).filter((l) => l.trim() !== '' && !/^\s*#/.test(l));
  if (upd === null) { if (body.length > 0) return by('the `updates:` block is not a block sequence'); return { content: `${nl}${entry}` }; }
  if (!Array.isArray(upd) || upd.length === 0) return by('`updates` is not a block sequence');
  if (!(body[0] ?? '').startsWith('  - ') || body.some((l) => !l.startsWith('  '))) return by('the items of `updates` are not a block sequence at the standard indentation');
  return { content: `${nl}${entry}` };
}
