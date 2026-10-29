// The commit the audit read (hand checks 2026-10-29, fix 10, ruling P55): HEAD's SHA and branch, read from .git as
// plain text, never by running git. The repo is attacker-controlled: every file goes through the read limits (1 MB,
// symbolic links refused at every level), a branch name must be a plain ref name (no `..`, no leading `/` or `-`), and
// only a 40- or 64-hex SHA is accepted. Anything else is null: the report says the commit couldn't be read.
import { join } from 'node:path';
import { linkedLevel, readTextLimitedWithReason, regexLines } from './limits.js';

export interface HeadCommit { sha: string; short: string; branch: string | null }

const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const BRANCH = /^(?!.*\.\.)(?!.*\/\/)(?!.*\/\.)(?!.*\.lock(?:\/|$))[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}(?<![./])$/;

async function readGit(dir: string, rel: string): Promise<string | null> {
  if ((await linkedLevel(dir, rel)) !== null) return null;
  const r = await readTextLimitedWithReason(join(dir, rel), dir);
  return 'text' in r ? r.text : null;
}

const commit = (sha: string, branch: string | null): HeadCommit => ({ sha, short: sha.slice(0, 7), branch });

/** HEAD's commit in the checkout at `dir` (a .git folder), or null when it can't be read safely. */
export async function readHeadCommit(dir: string): Promise<HeadCommit | null> {
  const head = (await readGit(dir, '.git/HEAD'))?.trim();
  if (head === undefined) return null;
  if (SHA.test(head)) return commit(head, null);
  const ref = /^ref: refs\/heads\/(.+)$/.exec(head)?.[1];
  if (ref === undefined || !BRANCH.test(ref)) return null;
  const loose = (await readGit(dir, `.git/refs/heads/${ref}`))?.trim();
  if (loose !== undefined) return SHA.test(loose) ? commit(loose, ref) : null;
  const packed = await readGit(dir, '.git/packed-refs');
  if (packed === null) return null;
  for (const line of regexLines(packed)) {
    const m = /^([0-9a-f]{40}|[0-9a-f]{64}) refs\/heads\/(.+)$/.exec(line.trim());
    if (m?.[2] === ref) return commit(m[1] as string, ref);
  }
  return null;
}
