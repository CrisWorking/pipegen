// The pure builders for the files Plan G writes and the D0b judges re-check (v0.2 Plan D, D0b; preflight 4.2). Plan G calls these to
// produce a CODEOWNERS block and a dependabot entry; the judges call the same functions and compare byte for byte (or value for value),
// so the producer and the referee can not drift. A leaf: types, the protected-path leaf and the gate's LOGIN_RE only.
import { LOGIN_RE, MAX_LINE, PIPEGEN_BLOCK_BEGIN, PIPEGEN_BLOCK_END } from '../../gate/src/integrity.js';
import type { PipelineDraft, ReviewedTool } from '../types.js';
import { effectiveProtectedPaths } from './protected-paths.js';
import { isObj, parseYaml } from './yaml-parse.js';

// ---------- CODEOWNERS ----------

// the gate reads the block by these exact lines (gate-v0.2.1: its owners waive findings in files no rule covers), so they are the gate's own constants
export const CODEOWNERS_BEGIN = PIPEGEN_BLOCK_BEGIN;
export const CODEOWNERS_END = PIPEGEN_BLOCK_END;
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
 * in place by the new block and every other byte stays. Returns null if `inserted` is not in the original exactly once, or does not start a line.
 */
export function codeownersReplace(original: string, inserted: string, block: string): string | null {
  const i = inserted === '' ? -1 : original.indexOf(inserted);
  if (i < 0 || original.indexOf(inserted, i + 1) >= 0) return null;
  if (i > 0 && original[i - 1] !== '\n') return null;   // the block starts a line; mid-line, the user's text before it would be read as part of a rule
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

// ---------- git hooks (v0.2 Plan G, G1: ruling B4) ----------

/** The three hook managers pipegen extends, and the one file of each it appends to (pipegen sets up lefthook when the repository has none). */
export type HookManager = 'pre-commit' | 'husky' | 'lefthook';
export const HOOK_FILES: Readonly<Record<HookManager, string>> = Object.freeze({ 'pre-commit': '.pre-commit-config.yaml', husky: '.husky/pre-commit', lefthook: 'lefthook.yml' });
/** The marker on the first line of pipegen's block (a comment in every manager's syntax): a re-run finds it and adds nothing twice. */
export const HOOKS_MARKER = 'pipegen:hooks';
const HOOKS_NOTE = "pipegen's reviewed hooks; the install record holds this text";
/**
 * The reviewed local hook commands, by reviewed entry id (B4: a hook runs only a reviewed, pinned command, never a hook repo URL): the tool's
 * argv on the developer's machine. The command names the reviewed package at its reviewed version (G1-R2 I3: `npx --no --package=<package>@<version>`),
 * so npx runs exactly that version from the local install and, with `--no`, never downloads one: a missing or other version fails the hook
 * instead of running something else (pipegen's devDependency edit adds that version with its integrity, Plan D D6). One row per tool whose
 * hook form is reviewed; G6 adds rows here (and only here) under review, and the judge follows, since it calls the same builder.
 */
export const HOOK_COMMANDS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  // biome checks format and lint of the staged files only (PC3), and passes when none of them is one it reads
  biome: Object.freeze(['biome', 'check', '--staged', '--no-errors-on-unmatched']),
});
/** One hook pipegen appends: its id (`pipegen-<tool>`) and its command line. */
export interface HookCommand { id: string; run: string }
const HOOK_RUN_RE = /^[A-Za-z0-9 ._@=:/-]{1,300}$/;
const NPM_PACKAGE_RE = /^(?:@[a-z0-9][a-z0-9._-]{0,100}\/)?[a-z0-9][a-z0-9._-]{0,100}$/;
const NPM_EXACT_VERSION_RE = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,40})?$/;
const HOOK_ID_RE = /^pipegen-[a-z0-9][a-z0-9-]{0,60}$/;
const isRootPath = (path: string): boolean => path === '' || path === '.' || path === './';
const sameReviewed = (a: unknown, t: ReviewedTool): boolean => {
  if (typeof a !== 'object' || a === null) return false;
  const c = a as Record<string, unknown>;
  const b = t.candidate;
  return c.source === 'reviewed' && c.reviewed === true && c.id === b.id && c.kind === b.kind && c.repo === b.repo && c.version === b.version && JSON.stringify(c.pin) === JSON.stringify(b.pin);
};

/**
 * The hooks pipegen appends for this draft (B4), in need order: for each pre-commit `format-lint` need of the ROOT service (an npm service:
 * the hook runs from the repository root, where every manager starts it), each reviewed tool of its steps (the entry at its reviewed pin,
 * installed by npm) that has a reviewed hook command. Empty: no hook to append (the builder then gives a note, the judge refuses any file).
 */
export function hookCommands(draft: PipelineDraft, reviewed: readonly ReviewedTool[]): HookCommand[] {
  const out: HookCommand[] = [];
  for (const need of draft.needs) {
    if (need.layer !== 'pre-commit' || need.id !== 'format-lint') continue;
    const svc = draft.profile.services.find((s) => s.name === need.service);
    if (svc === undefined || !isRootPath(svc.path) || svc.language !== 'node' || svc.packageManager !== 'npm') continue;
    for (const spec of draft.steps) {
      if (spec?.needId !== need.id || spec.service !== need.service) continue;
      const t = reviewed.find((r) => r.id === spec.tool?.id);
      const argv = t === undefined || !Object.hasOwn(HOOK_COMMANDS, t.id) ? undefined : HOOK_COMMANDS[t.id];
      const install = t?.step.cli?.install;
      if (t === undefined || argv === undefined || !sameReviewed(spec.tool, t) || install?.method !== 'npm') continue;
      if (!NPM_PACKAGE_RE.test(install.package) || typeof install.version !== 'string' || !NPM_EXACT_VERSION_RE.test(install.version)) throw new Error(`the reviewed package of ${t.id} is not an npm name at an exact version`);
      const hook: HookCommand = { id: `pipegen-${t.id}`, run: ['npx', '--no', `--package=${install.package}@${install.version}`, '--', ...argv].join(' ') };
      if (!HOOK_ID_RE.test(hook.id) || !HOOK_RUN_RE.test(hook.run)) throw new Error(`the hook command of ${t.id} is not plain text pipegen can write`);
      if (!out.some((h) => h.id === hook.id)) out.push(hook);
    }
  }
  return out;
}

/** pipegen's block for one manager: pre-commit a `repo: local` item at `indent` (no rev: it fetches nothing), husky plain lines, lefthook a `pre-commit` key. */
export function hookBlock(manager: HookManager, commands: readonly HookCommand[], indent = ''): string {
  const q = JSON.stringify;
  if (manager === 'husky') return [`# ${HOOKS_MARKER} begin: ${HOOKS_NOTE}`, ...commands.map((c) => c.run), `# ${HOOKS_MARKER} end`, ''].join('\n');
  if (manager === 'lefthook') return [`# ${HOOKS_MARKER}: ${HOOKS_NOTE}`, 'pre-commit:', '  commands:', ...commands.flatMap((c) => [`    ${c.id}:`, `      run: ${q(c.run)}`]), ''].join('\n');
  const i = indent;
  return [`${i}# ${HOOKS_MARKER}: ${HOOKS_NOTE}`, `${i}- repo: local`, `${i}  hooks:`,
    ...commands.flatMap((c) => [`${i}    - id: ${q(c.id)}`, `${i}      name: ${q(c.id)}`, `${i}      entry: ${q(c.run)}`, `${i}      language: system`, `${i}      pass_filenames: false`, `${i}      always_run: true`]), ''].join('\n');
}

/**
 * The whole hook file (B4, the D0a append pattern): the user's bytes untouched, then pipegen's block appended (a newline first when the file
 * does not end with one). `inserted` is everything after the original (the install record's EditKind 'hooks' text). Only shapes pipegen can
 * append to safely; any other, a file that already holds pipegen's block, CR line ends or tabs, or no hook command at all give no file and a note.
 * - pre-commit: `repos:` is the last top-level key, written as a plain key line, its items a block sequence at indentation 0 or 2 (a new file: `repos:` then the block);
 * - husky: plain shell lines; no line continuation at the end and no here-document (either would swallow pipegen's lines);
 * - lefthook: no `pre-commit` key yet (pipegen adds the whole key; it never edits the user's hooks).
 */
export function hookFile(manager: HookManager, original: string, draft: PipelineDraft, reviewed: readonly ReviewedTool[]): { content: string; inserted: string } | { note: string } {
  if (typeof original !== 'string') return { note: 'the original text of the hook file is missing' };
  let commands: HookCommand[];
  try { commands = hookCommands(draft, reviewed); } catch (e) { return { note: e instanceof Error ? e.message : 'the hook commands can not be built' }; }
  if (commands.length === 0) return { note: 'pipegen has no reviewed hook command for this repository (a format and lint check of the root npm service with a tool whose hook form is reviewed), so it adds no hook' };
  if (original.includes(HOOKS_MARKER)) return { note: `the ${HOOK_FILES[manager]} file already holds pipegen's hooks, so pipegen adds them no second time` };
  const by = (why: string): { note: string } => ({ note: `pipegen can not add its hooks to ${HOOK_FILES[manager]} safely (${why}); add them by hand:\n${hookBlock(manager, commands)}` });
  if (/[\r\t]/.test(original)) return by('it uses CRLF line ends or tabs');
  const nl = original === '' || original.endsWith('\n') ? original : `${original}\n`;
  const done = (block: string): { content: string; inserted: string } => ({ content: nl + block, inserted: (nl + block).slice(original.length) });
  // G1-R2 I4: the result must parse strictly as ONE document holding the user's data plus exactly pipegen's hooks (a flow map, a document end
  // marker or a second document in the original would leave a broken file, or one whose hooks never run)
  const checked = (out: { content: string; inserted: string }): { content: string; inserted: string } | { note: string } => {
    const problem = hookDataProblem(manager, original, out.content, commands);
    return problem === null ? out : by(problem);
  };
  if (manager === 'husky') {
    const lines = original.split('\n').filter((l) => l.trim() !== '');
    if (/\\\s*$/.test(lines[lines.length - 1] ?? '')) return by('its last line continues onto the next');
    const why = huskyAppendProblem(original);
    if (why !== null) return by(why);
    return done(hookBlock('husky', commands));
  }
  if (manager === 'lefthook') {
    if (original !== '') {
      const r = parseYaml(original, 'strict');
      if ('problems' in r) return by(`it does not parse strictly: ${r.problems.join('; ')}`);
      if (Object.hasOwn(r.parsed.js, 'pre-commit')) return by('it already has a pre-commit key, which pipegen does not edit');
    }
    return checked(done(hookBlock('lefthook', commands)));
  }
  if (original === '') return checked(done(`repos:\n${hookBlock('pre-commit', commands)}`));
  const r = parseYaml(original, 'strict');
  if ('problems' in r) return by(`it does not parse strictly: ${r.problems.join('; ')}`);
  const keys = Object.keys(r.parsed.js);
  if (keys[keys.length - 1] !== 'repos' || !Array.isArray(r.parsed.js.repos) || r.parsed.js.repos.length === 0) return by('`repos` is not the last top-level key with a list of repos');
  const lines = original.split('\n');
  const at = lines.map((l, i) => (/^repos:[ ]*(?:#.*)?$/.test(l) ? i : -1)).filter((i) => i >= 0);
  if (at.length !== 1) return by('`repos:` is not written as a plain key line');
  const body = lines.slice((at[0] as number) + 1).filter((l) => l.trim() !== '' && !/^\s*#/.test(l));
  const indent = /^( *)- /.exec(body[0] ?? '')?.[1];
  if (indent === undefined || (indent !== '' && indent !== '  ') || body.some((l) => !l.startsWith(`${indent}- `) && !l.startsWith(`${indent} `))) return by('the repos are not a block sequence at indentation 0 or 2');
  return checked(done(hookBlock('pre-commit', commands, indent)));
}

/** The data a hook manager reads from pipegen's block (pre-commit's local repo item, lefthook's pre-commit key). */
function hookData(manager: 'pre-commit' | 'lefthook', commands: readonly HookCommand[]): unknown {
  if (manager === 'lefthook') return { commands: Object.fromEntries(commands.map((c) => [c.id, { run: c.run }])) };
  return { repo: 'local', hooks: commands.map((c) => ({ id: c.id, name: c.id, entry: c.run, language: 'system', pass_filenames: false, always_run: true })) };
}
/**
 * Why an appended YAML hook file is not the user's data plus exactly pipegen's (G1-R2 I4), or null: both texts parse strictly as one document
 * each; for lefthook the result is the original map plus the new `pre-commit` key; for pre-commit its `repos` are the original's plus pipegen's
 * local item, and every other key is unchanged.
 */
export function hookDataProblem(manager: HookManager, original: string, content: string, commands: readonly HookCommand[]): string | null {
  if (manager === 'husky') return null;
  const before = original === '' ? { parsed: { js: manager === 'pre-commit' ? { repos: [] } : {} } } : parseYaml(original, 'strict');
  const after = parseYaml(content, 'strict');
  if ('problems' in before) return `the original does not parse as one strict YAML document (${before.problems.join('; ')})`;
  if ('problems' in after) return `the file with the hooks appended would not parse as one strict YAML document (${after.problems.join('; ')}), so the manager would read no hook of pipegen's`;
  const a = before.parsed.js as Record<string, unknown>;
  const b = after.parsed.js;
  const want = manager === 'lefthook'
    ? { ...a, 'pre-commit': hookData('lefthook', commands) }
    : { ...a, repos: [...(Array.isArray(a.repos) ? a.repos : []), hookData('pre-commit', commands)] };
  if (JSON.stringify(sortKeys(b)) !== JSON.stringify(sortKeys(want))) return 'the file with the hooks appended would not read as the original plus exactly pipegen\'s hooks';
  return null;
}
const sortKeys = (v: unknown): unknown => (Array.isArray(v) ? v.map(sortKeys) : isObj(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v);

/**
 * Why pipegen's lines appended to a husky script might never run, or run as something else (G1-R2 m4), or null. Shell can not be judged
 * whole, so this refuses what makes it unclear: `exit` or `exec` anywhere outside a comment, any here-document or here-string (`<<`), a quote
 * left open, and an `if`/`case`/loop or a brace or parenthesis left open at the end. A refused script gets no append and a note.
 */
export function huskyAppendProblem(original: string): string | null {
  // the code outside comments and quoted strings (quoted text kept as an empty pair, so a word inside a string is not a keyword)
  let code = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < original.length; i++) {
    const c = original[i] as string;
    if (quote === "'") { if (c === "'") { quote = null; code += "'"; } continue; }
    if (quote === '"') { if (c === '\\') { i++; continue; } if (c === '"') { quote = null; code += '"'; } continue; }
    if (c === '\\') { code += c + (original[i + 1] ?? ''); i++; continue; }
    if (c === "'" || c === '"') { quote = c; code += c; continue; }
    if (c === '#' && (i === 0 || /\s/.test(original[i - 1] as string))) { while (i < original.length && original[i] !== '\n') i++; code += '\n'; continue; }
    code += c;
  }
  if (quote !== null) return 'it leaves a quote open at its end';
  if (/\b(?:exit|exec)\b/.test(code)) return 'it has an exit or exec, after which appended lines would not run';
  if (code.includes('<<')) return 'it has a here-document or here-string';
  const n = (re: RegExp): number => (code.match(re) ?? []).length;
  const word = (w: string): RegExp => new RegExp(`(?:^|[\\s;&|(){}])${w}(?=$|[\\s;&|(){}])`, 'g');
  if (n(word('if')) !== n(word('fi'))) return 'an if is left open at its end';
  if (n(word('case')) !== n(word('esac'))) return 'a case is left open at its end';
  if (n(word('for')) + n(word('while')) + n(word('until')) + n(word('select')) !== n(word('done'))) return 'a loop is left open at its end';
  if (n(/\{/g) !== n(/\}/g) || n(/\(/g) !== n(/\)/g)) return 'a brace or parenthesis is left open at its end';
  return null;
}
