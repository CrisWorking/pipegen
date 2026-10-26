import { lstat, readFile } from 'node:fs/promises';
import fg from 'fast-glob';
import { parse as parseYaml } from 'yaml';

/** Read limits that protect the user's machine from hostile repos. Every reader goes through this file. */
export const READ_LIMITS = { maxFileBytes: 1_000_000, maxFiles: 20_000, maxAliasCount: 50, maxRegexLineBytes: 4096 } as const;

/** Folders never read: dependencies, VCS data, virtualenvs and build output. */
export const IGNORED_DIRS: readonly string[] = Object.freeze(['node_modules', '.git', '.venv', 'dist', 'build', 'vendor', 'target']);

/**
 * Lists files under `dir` (relative, forward slashes). Never follows symlinks; stops after maxFiles.
 * When `found` is given, symbolic links met on the way (to files or folders) are collected in
 * `found.links` (at most maxFiles of them) so callers can say what they skipped; they are never followed.
 */
export async function listFiles(dir: string, patterns: string[], ignore: string[], found?: { links: string[] }): Promise<{ files: string[]; truncated: boolean }> {
  const stream = fg.stream(patterns, { cwd: dir, ignore, dot: true, onlyFiles: !found, objectMode: !!found, unique: true, suppressErrors: true, followSymbolicLinks: false });
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
      return { files, truncated: true };
    }
    files.push(rel);
  }
  return { files, truncated: false };
}

/** A NUL byte in the first 8 KB means binary. */
export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

export type Skipped = 'too-large' | 'binary' | 'link' | 'not-a-file' | 'unreadable';

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
