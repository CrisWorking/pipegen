// Directories pipegen keeps files in that must not be tampered with (the tool cache, the memory of proven tools).
// OpenSSH StrictModes style: every directory from the folder up to `/` must be a real directory (not a symlink),
// owned by you (pipegen's own levels) or by you or root (the rest), and have no group or other write, except a
// root-owned sticky directory such as /tmp. So nobody else can swap a file between its check and its use.
import { lstat, mkdir, realpath } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/** What the messages say, and which error to throw (each caller has its own error class). */
export interface TrustedDirKind {
  /** e.g. "tool cache" */
  noun: string;
  /** e.g. "tools" (pipegen won't keep ___ under …) */
  keeping: string;
  /** e.g. "swap the tool pipegen runs" */
  risk: string;
  error: (message: string, cause?: unknown) => Error;
}

const errCode = (e: unknown) => (e as { code?: unknown } | null)?.code;

/** Creates a directory 0700 when it is missing (with its parents when `parents`). An existing one is checked later. */
export async function mkdirOwn(dir: string, parents: boolean, kind: TrustedDirKind): Promise<void> {
  try {
    await mkdir(dir, { mode: 0o700, recursive: parents });
  } catch (e) {
    if (errCode(e) !== 'EEXIST') throw kind.error(`Couldn't create pipegen's ${kind.noun} directory ${dir}.`, e);
  }
}

export async function realDir(dir: string, kind: TrustedDirKind): Promise<string> {
  try {
    return await realpath(dir);
  } catch (e) {
    throw kind.error(`Couldn't resolve pipegen's ${kind.noun} directory ${dir}.`, e);
  }
}

/** One directory on the path to the file: see the header. `pipegenOwned` levels must belong to you, not root. */
export async function checkDir(dir: string, uid: number, pipegenOwned: boolean, kind: TrustedDirKind): Promise<void> {
  const refuse = (why: string, fix = ''): never => {
    throw kind.error(`pipegen won't keep ${kind.keeping} under ${dir}: ${why}.${fix === '' ? '' : ` Fix it with: ${fix}`}`);
  };
  let info;
  try {
    info = await lstat(dir);
  } catch (e) {
    throw kind.error(`Couldn't check pipegen's ${kind.noun} directory ${dir}.`, e);
  }
  if (info.isSymbolicLink()) refuse('it is a symbolic link where pipegen keeps its own folder', `rm '${dir}'`);
  if (!info.isDirectory()) refuse('it is not a directory');
  const rootOwned = info.uid === 0;
  if (info.uid !== uid && (pipegenOwned || !rootOwned)) refuse('it is not owned by you' + (pipegenOwned ? '' : ' (or root)'));
  const sticky = (info.mode & 0o1000) !== 0;
  if ((info.mode & 0o022) !== 0 && !(rootOwned && sticky && !pipegenOwned)) {
    refuse(`other users can write to it, so they could ${kind.risk}`, `chmod g-w,o-w '${dir}'`);
  }
}

/** Checks `root` and every directory above it up to `/`. `rootOwned`: root itself is one of pipegen's own levels. */
export async function checkChain(root: string, uid: number, rootOwned: boolean, kind: TrustedDirKind): Promise<void> {
  for (let dir = root; ; dir = dirname(dir)) {
    await checkDir(dir, uid, rootOwned && dir === root, kind);
    if (dirname(dir) === dir) break;
  }
}

/**
 * Prepares `<root>/<own...>`: `root` is created if missing (with parents), resolved to its real path, and checked
 * with everything above it. Then each of pipegen's own levels is created 0700 and checked before anything is
 * created inside it. `rootOwned`: the given root is itself pipegen's own folder. Returns the final directory.
 */
export async function prepareTrustedDir(root: string, own: string[], rootOwned: boolean, uid: number, kind: TrustedDirKind): Promise<string> {
  await mkdirOwn(root, true, kind);
  const real = await realDir(root, kind);
  await checkChain(real, uid, rootOwned, kind);
  let dir = real;
  for (const part of own) {
    dir = join(dir, part);
    await mkdirOwn(dir, false, kind);
    await checkDir(dir, uid, true, kind);
  }
  return dir;
}
