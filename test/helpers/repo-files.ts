// The repo's own files, for the guard tests that read every source and test file (no-secret-literals, no-raw-controls).
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

export const root = resolve(import.meta.dirname, '../..');

/** Every regular file under `dir` (repo-relative, forward slashes), for when git is not available (a tarball, no git). */
export function walkFiles(dir: string): string[] {
  return readdirSync(join(root, dir), { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => relative(root, join(e.parentPath, e.name)).split('\\').join('/'))
    .sort();
}

/** Committed files plus new files not yet committed (not ignored), so the check also covers the working tree. Without git, a walk. */
export function repoFiles(dir: string): string[] {
  try {
    const out = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', dir], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out.split('\0').filter(Boolean);
  } catch {
    return walkFiles(dir);
  }
}
