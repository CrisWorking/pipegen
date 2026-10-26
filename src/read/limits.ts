import { lstat, readFile } from 'node:fs/promises';
import fg from 'fast-glob';
import { parse as parseYaml } from 'yaml';

/** Read limits that protect the user's machine from hostile repos. Every reader goes through this file. */
export const READ_LIMITS = { maxFileBytes: 1_000_000, maxFiles: 20_000, maxAliasCount: 50, maxRegexLineBytes: 4096 } as const;

/** Lists files under `dir` (relative, forward slashes). Never follows symlinks; stops after maxFiles. */
export async function listFiles(dir: string, patterns: string[], ignore: string[]): Promise<{ files: string[]; truncated: boolean }> {
  const stream = fg.stream(patterns, { cwd: dir, ignore, dot: true, onlyFiles: true, unique: true, suppressErrors: true, followSymbolicLinks: false });
  const files: string[] = [];
  for await (const entry of stream) {
    if (files.length >= READ_LIMITS.maxFiles) {
      (stream as unknown as { destroy(): void }).destroy();
      return { files, truncated: true };
    }
    files.push(String(entry));
  }
  return { files, truncated: false };
}

/** A NUL byte in the first 8 KB means binary. */
export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

/** Text of a regular file, or null when it is missing, a symlink, over 1 MB, or binary. */
export async function readTextLimited(path: string): Promise<string | null> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.size > READ_LIMITS.maxFileBytes) return null;
    const buf = await readFile(path);
    return isBinary(buf) ? null : buf.toString('utf8');
  } catch {
    return null;
  }
}

/** YAML with at most 50 aliases (guards against alias-bomb files). Throws when the limit is exceeded. */
export function parseYamlLimited(text: string): unknown {
  return parseYaml(text, { maxAliasCount: READ_LIMITS.maxAliasCount });
}

/** Only the lines of 4 KB or less; regex rules run on these so a huge line cannot stall a pattern. */
export function regexLines(text: string): string[] {
  return text.split(/\r?\n/).filter((line) => Buffer.byteLength(line) <= READ_LIMITS.maxRegexLineBytes);
}
