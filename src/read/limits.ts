import { lstat, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import fg from 'fast-glob';
import { parse as parseYaml } from 'yaml';

/** Read limits that protect the user's machine from hostile repos. Every reader goes through this file. */
export const READ_LIMITS = { maxFileBytes: 1_000_000, maxFiles: 20_000, maxAliasCount: 50, maxRegexLineBytes: 4096 } as const;

/** Folders never read: dependencies, VCS data, virtualenvs and build output. */
export const IGNORED_DIRS: readonly string[] = Object.freeze(['node_modules', '.git', '.venv', 'dist', 'build', 'vendor', 'target']);

/**
 * The first level of `rel` (a fixed path inside `dir`) that is a symbolic link, or null. A missing level ends the check.
 * Exported for the coverage mapper, which checks every level of a file it reads by path.
 */
export async function linkedLevel(dir: string, rel: string): Promise<string | null> {
  const parts = rel.split('/').filter((p) => p !== '' && p !== '.');
  for (let i = 0; i < parts.length; i++) {
    const info = await lstat(join(dir, ...parts.slice(0, i + 1))).catch(() => null);
    if (info === null) return null;
    if (info.isSymbolicLink()) return parts.slice(0, i + 1).join('/');
  }
  return null;
}

/**
 * Lists files under `dir` (relative, forward slashes). Never follows symlinks; stops after maxFiles.
 * A pattern whose fixed base (`.github/workflows` in `.github/workflows/*.yml`) passes through a symbolic link is
 * skipped, because the glob library would open that base by path and so follow the link; the link is reported
 * in `links` (only present when there is one).
 * When `found` is given, symbolic links met on the way (to files or folders) are collected in
 * `found.links` (at most maxFiles of them) so callers can say what they skipped; they are never followed.
 */
export async function listFiles(dir: string, patterns: string[], ignore: string[], found?: { links: string[] }): Promise<{ files: string[]; truncated: boolean; links?: string[] }> {
  const links: string[] = [];
  const usable: string[] = [];
  for (const pattern of patterns) {
    // The bases fast-glob will actually open: braces in a folder part (`l{n,x}k/*`) expand to several fixed bases.
    const bases = pattern.startsWith('!') ? [] : fg.generateTasks([pattern], { cwd: dir }).map((t) => t.base).filter((b) => b !== '.' && b !== '');
    let link: string | null = null;
    for (const base of bases) if (link === null) link = await linkedLevel(dir, base);
    if (link !== null) {
      if (!links.includes(link)) links.push(link);
      if (found && found.links.length < READ_LIMITS.maxFiles && !found.links.includes(link)) found.links.push(link);
      continue;
    }
    usable.push(pattern);
  }
  const done = (files: string[], truncated: boolean) => (links.length > 0 ? { files, truncated, links } : { files, truncated });
  if (usable.length === 0) return done([], false);
  const stream = fg.stream(usable, { cwd: dir, ignore, dot: true, onlyFiles: !found, objectMode: !!found, unique: true, suppressErrors: true, followSymbolicLinks: false });
  const files: string[] = [];
  for await (const entry of stream) {
    let rel: string;
    if (found) {
      const e = entry as unknown as { path: string; dirent: { isFile(): boolean; isSymbolicLink(): boolean } };
      if (e.dirent.isSymbolicLink()) {
        if (found.links.length < READ_LIMITS.maxFiles) found.links.push(e.path);
        continue;
      }
      if (!e.dirent.isFile()) continue;
      rel = e.path;
    } else {
      rel = String(entry);
    }
    if (files.length >= READ_LIMITS.maxFiles) {
      (stream as unknown as { destroy(): void }).destroy();
      return done(files, true);
    }
    files.push(rel);
  }
  return done(files, false);
}

/** A NUL byte in the first 8 KB means binary. */
export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

export type Skipped = 'too-large' | 'binary' | 'link' | 'not-a-file' | 'unreadable';

/** Why a file was skipped, in plain English, for notes: `Skipped <path>: <reason>.` */
export const SKIP_REASON: Readonly<Record<Skipped, string>> = Object.freeze({
  'too-large': 'it is larger than 1 MB',
  binary: 'it is a binary file',
  link: 'it is a symbolic link',
  'not-a-file': 'it is not a regular file',
  unreadable: 'it could not be read',
});

/** READ_LIMITS.maxFiles as people write it (20,000). */
export const MAX_FILES_TEXT = READ_LIMITS.maxFiles.toLocaleString('en-US');

/** Like readTextLimited, but says why a file was skipped. */
export async function readTextLimitedWithReason(path: string): Promise<{ text: string } | { skipped: Skipped }> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return { skipped: 'link' };
    if (!info.isFile()) return { skipped: 'not-a-file' };
    if (info.size > READ_LIMITS.maxFileBytes) return { skipped: 'too-large' };
    const buf = await readFile(path);
    return isBinary(buf) ? { skipped: 'binary' } : { text: buf.toString('utf8') };
  } catch {
    return { skipped: 'unreadable' };
  }
}

/** Text of a regular file, or null when it is missing, unreadable, a symlink, over 1 MB, or binary. */
export async function readTextLimited(path: string): Promise<string | null> {
  const result = await readTextLimitedWithReason(path);
  return 'text' in result ? result.text : null;
}

/** YAML with at most 50 aliases (guards against alias-bomb files). Throws when the limit is exceeded. */
export function parseYamlLimited(text: string): unknown {
  return parseYaml(text, { maxAliasCount: READ_LIMITS.maxAliasCount });
}

/** Only the lines of 4 KB or less; regex rules run on these so a huge line cannot stall a pattern. */
export function regexLines(text: string): string[] {
  return text.split(/\r?\n/).filter(regexSafe);
}

/** True when a repo-derived string is short enough (4 KB) to run a regex on. */
export function regexSafe(s: string): boolean {
  return Buffer.byteLength(s) <= READ_LIMITS.maxRegexLineBytes;
}
