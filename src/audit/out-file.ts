// `pipegen audit --out <file>`: writes the report to a file without letting the audited repo choose a different
// file (threat T42: a planted symlink, or a symlinked folder, that turns the write into "overwrite ~/.bashrc").
// Ruling S20:
// - a relative path is read from the current folder, never from `--dir`; folders are never created;
// - POSIX: open with no-follow + exclusive create (`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600), so a symlink
//   or any existing file is refused. `--force` replaces an existing REGULAR file only: lstat before the open,
//   fstat after it, the same dev/ino on both, one hard link; a symlink, FIFO, device or folder is refused;
// - Windows (no O_NOFOLLOW in fs.constants): lstat first and refuse a symlink/junction, then `wx` (exclusive
//   create, which also refuses any other existing reparse point); `--force` is refused there;
// - everywhere: a target inside `--dir` is refused without `--force`, and every folder from `--dir` down to the
//   target's folder must be a real folder, not a symlink (with or without `--force`).
//
// Deviation from S20 (stronger, same intent): `--force` opens WITHOUT `O_TRUNC` and empties the file only after
// fstat proved it is the regular file lstat saw. With `O_TRUNC` the open itself would empty a file swapped in
// between lstat and open, before the dev/ino check could refuse it. `O_NONBLOCK` is added so a FIFO swapped in
// there makes the open fail at once (ENXIO) instead of hanging until a reader appears.
import { constants as fsConstants } from 'node:fs';
import { lstat, open as fsOpen, realpath, stat, type FileHandle } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { OUTPUT_CAP } from '../util/safe-output.js';
import { safeText } from '../util/safe-text.js';

/** A refusal or failure with a plain-English message, ready to print as is (no stack, no cause). */
export class OutFileError extends Error {
  override name = 'OutFileError';
}

export type OpenFn = (path: string, flags: string | number, mode?: number) => Promise<FileHandle>;

/** The open flags writeOutFile uses. `O_NOFOLLOW` is undefined on Windows, which selects the Windows branch. */
export interface OutFileConstants {
  O_WRONLY: number;
  O_CREAT: number;
  O_EXCL: number;
  O_NOFOLLOW?: number;
  O_NONBLOCK?: number;
}

export interface WriteOutFileOptions {
  /** Allow replacing an existing regular file, and writing inside `dir`. */
  force: boolean;
  /** The audited repo (`--dir`). Pass it always, also when it defaults to the current folder. */
  dir?: string;
  /** The current folder (tests). Default: process.cwd(). */
  cwd?: string;
  /** Platform open flags (tests). Default: fs.constants. */
  constants?: OutFileConstants;
  /** fs.promises.open (tests). */
  open?: OpenFn;
}

const MODE = 0o600;

const errCode = (e: unknown): unknown => (e as { code?: unknown } | null)?.code;

const show = (p: string) => safeText(p, OUTPUT_CAP.path);

/** Plain words for the fs errors a user can meet here; never the raw message (it repeats the uncleaned path). */
function reason(e: unknown): string {
  switch (errCode(e)) {
    case 'EACCES':
    case 'EPERM':
      return 'permission denied';
    case 'ENOENT':
      return "its folder doesn't exist (pipegen doesn't create folders)";
    case 'ENOTDIR':
      return 'a part of the path is not a folder';
    case 'EISDIR':
      return 'it is a folder';
    case 'ENOSPC':
      return 'the disk is full';
    case 'EDQUOT':
      return 'your disk quota is full';
    case 'EROFS':
      return 'the disk is read-only';
    case 'ENAMETOOLONG':
      return 'the path is too long';
    default: {
      const code = errCode(e);
      return typeof code === 'string' && /^E[A-Z0-9]+$/.test(code) ? `system error ${code}` : 'unexpected error';
    }
  }
}

async function lstatOrNull(p: string): Promise<Stats | null> {
  try {
    return await lstat(p);
  } catch (e) {
    if (errCode(e) === 'ENOENT') return null;
    throw e;
  }
}

async function realOrNull(p: string): Promise<string | null> {
  try {
    return await realpath(p);
  } catch {
    return null;
  }
}

/** `p` is `base` or below it (both absolute and normalized). */
function within(base: string, p: string): boolean {
  const rel = relative(base, p);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Writes `content` to `path` (the `--out` file) under ruling S20 (see the header). Throws OutFileError with a
 * plain message on every refusal or failure; the message is safe to print.
 */
export async function writeOutFile(path: string, content: string, opts: WriteOutFileOptions): Promise<void> {
  const c = opts.constants ?? fsConstants;
  const open = opts.open ?? fsOpen;
  const cwd = opts.cwd ?? process.cwd();
  const noFollow = c.O_NOFOLLOW;
  const posix = typeof noFollow === 'number';

  if (typeof path !== 'string' || path === '') throw new OutFileError('--out needs a file name.');
  const target = resolve(cwd, path);
  const folder = dirname(target);
  const refuse = (why: string): never => {
    throw new OutFileError(`pipegen won't write the report to ${show(target)}: ${why}.`);
  };
  const fail = (e: unknown): never => {
    if (e instanceof OutFileError) throw e;
    if (typeof errCode(e) !== 'string') throw e; // not an fs error: a bug, keep it visible
    throw new OutFileError(`Couldn't write the report to ${show(target)}: ${reason(e)}.`);
  };

  if (!posix && opts.force) {
    throw new OutFileError(
      `--force isn't available on this system: pipegen can't replace ${show(target)} here without the risk of ` +
        'following a link to another file. Delete the old file first, or choose a new file name.',
    );
  }

  try {
    // The folder must already exist; it may be your own symlink when it is outside the repo.
    let folderInfo: Stats;
    try {
      folderInfo = await stat(folder);
    } catch (e) {
      if (errCode(e) === 'ENOENT') refuse(`the folder ${show(folder)} doesn't exist, and pipegen doesn't create folders`);
      throw e;
    }
    if (!folderInfo.isDirectory()) refuse(`${show(folder)} is not a folder`);

    const dir = opts.dir === undefined ? null : resolve(cwd, opts.dir);
    const inRepo = dir !== null && (await checkRepoFolders(dir, folder, refuse));

    const pre = await lstatOrNull(target);
    if (pre?.isSymbolicLink()) refuse('it is a symbolic link, which could point to another file');
    if (inRepo && !opts.force) {
      refuse(
        `it is inside the repo you are auditing (${show(dir)}). Don't write the report into the repo you're ` +
          'auditing: choose a file outside it, or add --force to write it there anyway',
      );
    }
    const exists = posix
      ? 'the file already exists. Add --force to replace it, or choose a new file name'
      : 'the file already exists. Delete it first, or choose a new file name';
    if (pre !== null) {
      if (!posix || !opts.force) refuse(exists);
      if (!pre.isFile()) refuse('it is not a regular file');
      if (pre.nlink > 1) refuse('it has other hard links, so replacing it would change another file too');
    }

    const flags = !posix
      ? 'wx'
      : opts.force
        ? c.O_WRONLY | c.O_CREAT | noFollow | (c.O_NONBLOCK ?? 0)
        : c.O_WRONLY | c.O_CREAT | c.O_EXCL | noFollow;
    let fh: FileHandle;
    try {
      fh = await open(target, flags, MODE);
    } catch (e) {
      const code = errCode(e);
      // Something appeared or changed between the checks and the open: say what it is now.
      if (code === 'EEXIST' || code === 'ELOOP' || code === 'EMLINK' || code === 'EFTYPE') {
        const now = await lstatOrNull(target).catch(() => null);
        if (now?.isSymbolicLink() || code !== 'EEXIST') refuse('it is a symbolic link, which could point to another file');
        refuse(exists);
      }
      if (code === 'ENXIO' || code === 'EISDIR') refuse('it is not a regular file');
      throw e;
    }

    try {
      const st = await fh.stat();
      if (!st.isFile()) refuse('it is not a regular file');
      if (st.nlink > 1) refuse('it has other hard links, so replacing it would change another file too');
      if (pre !== null && (st.dev !== pre.dev || st.ino !== pre.ino)) {
        refuse('the file changed while pipegen was writing the report. Nothing was written; try again');
      }
      if (opts.force) await fh.truncate(0);
      await fh.writeFile(content, 'utf8');
    } finally {
      await fh.close();
    }
  } catch (e) {
    fail(e);
  }
}

/**
 * Whether the target's folder is inside the audited repo, checked on the path as given and on the real path (so
 * your own link that leads into the repo counts too). When it is, every folder from the repo down to the target's
 * folder must be a real folder, not a symlink.
 */
async function checkRepoFolders(dir: string, folder: string, refuse: (why: string) => never): Promise<boolean> {
  let base: string | null = null;
  let below = folder;
  if (within(dir, folder)) {
    base = dir;
  } else {
    const realDir = await realOrNull(dir);
    const realFolder = await realOrNull(folder);
    if (realDir !== null && realFolder !== null && within(realDir, realFolder)) {
      base = realDir;
      below = realFolder;
    }
  }
  if (base === null) return false;

  let cur = base;
  for (const part of relative(base, below).split(sep).filter((s) => s !== '')) {
    cur = join(cur, part);
    const info = await lstatOrNull(cur);
    if (info === null) refuse(`the folder ${show(cur)} doesn't exist, and pipegen doesn't create folders`);
    if (info.isSymbolicLink()) {
      refuse(`the folder ${show(cur)} inside the repo is a symbolic link, which could point outside the repo`);
    }
    if (!info.isDirectory()) refuse(`${show(cur)} is not a folder`);
  }
  return true;
}
