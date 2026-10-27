// `pipegen audit --out <file>`: writes the report to a file without letting the audited repo choose a different
// file (threat T42: a planted symlink, or a symlinked folder, that turns the write into "overwrite ~/.bashrc").
// Ruling S20 (+ U19, + the T4a fix round 1):
// - a relative path is read from the current folder, never from `--dir`; folders are never created;
// - the target's folder is resolved one part at a time (lstat, then readlink for a link, like realpath). Before a
//   link is followed, the folder that holds it is compared with the repo BY IDENTITY (dev/ino of each ancestor vs
//   the dev/ino of `--dir`'s real folder), so no spelling of either path (your own link to the repo, a logical vs
//   physical current folder, /proc/self/cwd, macOS /tmp -> /private/tmp, letter case) can hide a link planted in
//   the repo: a link held by the repo or a folder below it is refused, with or without `--force`. realpath is never
//   called on the target's folder (it would follow the planted link). Any error while resolving refuses;
// - "inside the repo" uses the same identity check, and needs `--force` ("don't write the report into the repo
//   you're auditing");
// - POSIX: a target that doesn't exist is created exclusively (`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK`,
//   mode 0600), so a symlink or any existing file is refused, and a parent folder swapped after the checks can at
//   worst create a NEW file elsewhere, never overwrite one. `--force` on an existing REGULAR, single-link file
//   opens it with `O_WRONLY|O_NOFOLLOW|O_NONBLOCK` (no O_CREAT, no O_TRUNC), checks fstat = the lstat dev/ino,
//   then sets mode 0600 and only then empties it. A symlink, FIFO, device, folder or hard-linked file is refused;
//   `O_NONBLOCK` makes a FIFO swapped in fail at once (ENXIO) instead of hanging;
// - Linux: after the open, /proc/self/fd/<fd> tells which folder the file really is in; when it isn't the folder
//   that was checked (a parent swapped after the checks), nothing is written;
// - Windows (no O_NOFOLLOW in fs.constants): the same folder walk, lstat and refuse a symlink/junction, then `wx`
//   (exclusive create, which also refuses any other existing reparse point); `--force` is refused there.
import { constants as fsConstants, type BigIntStats } from 'node:fs';
import { lstat, open as fsOpen, readlink, stat, type FileHandle } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
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
  /** The audited repo (`--dir`), also when it defaults to the current folder. Resolved from `cwd`. */
  dir: string;
  /** The current folder (tests). Default: process.cwd(). */
  cwd?: string;
  /** Platform open flags (tests). Default: fs.constants. */
  constants?: OutFileConstants;
  /** fs.promises.open (tests). */
  open?: OpenFn;
}

const MODE = 0o600;
/** Links followed while resolving the target's folder, as Linux's own limit. */
const MAX_LINKS = 40;

const errCode = (e: unknown): unknown => (e as { code?: unknown } | null)?.code;
/** An operating-system error (EACCES, ENOSPC, ...), as opposed to Node's own ERR_* programming errors. */
const isSystemError = (e: unknown) => {
  const code = errCode(e);
  return typeof code === 'string' && /^E[A-Z0-9]+$/.test(code);
};

const show = (p: string) => safeText(p, OUTPUT_CAP.path);
const SYMLINK = 'it is a symbolic link, which could point to another file';
const NOT_REGULAR = 'it is not a regular file';
const HARD_LINKS = 'it has other hard links, so replacing it would change another file too';
const CHANGED = 'the file changed while pipegen was writing the report. Nothing was written; try again';

/** Plain words for the system errors a user can meet here; never the raw message (it repeats the uncleaned path). */
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
    case 'ELOOP':
      return 'the path has a symbolic-link loop';
    case 'ENOSPC':
      return 'the disk is full';
    case 'EDQUOT':
      return 'your disk quota is full';
    case 'EROFS':
      return 'the disk is read-only';
    case 'ENAMETOOLONG':
      return 'the path is too long';
    default:
      return `system error ${String(errCode(e))}`;
  }
}

async function lstatOrNull(p: string): Promise<BigIntStats | null> {
  try {
    return await lstat(p, { bigint: true });
  } catch (e) {
    if (errCode(e) === 'ENOENT') return null;
    throw e;
  }
}

const sameFile = (a: BigIntStats, b: BigIntStats) => a.dev === b.dev && a.ino === b.ino;
const splitParts = (p: string) => p.split(sep === '\\' ? /[\\/]/ : '/').filter((s) => s !== '' && s !== '.');
const endsWithSeparator = (p: string) => p.endsWith('/') || (sep === '\\' && p.endsWith('\\'));

/**
 * Writes `content` to `path` (the `--out` file) under ruling S20 (see the header). Throws OutFileError with a
 * plain message on every refusal or failure; the message is safe to print. Node's own ERR_* errors (bugs) are
 * rethrown as they are.
 */
export async function writeOutFile(path: string, content: string, opts: WriteOutFileOptions): Promise<void> {
  const c = opts.constants ?? fsConstants;
  const open = opts.open ?? fsOpen;
  const cwd = opts.cwd ?? process.cwd();
  const noFollow = c.O_NOFOLLOW;
  const posix = typeof noFollow === 'number';

  if (typeof path !== 'string' || path === '') throw new OutFileError('--out needs a file name.');
  const target = resolve(cwd, path);
  const refuse = (why: string): never => {
    throw new OutFileError(`pipegen won't write the report to ${show(target)}: ${why}.`);
  };
  if (endsWithSeparator(path) || basename(target) === '') refuse('it ends with a folder separator. Give a file name');

  if (!posix && opts.force) {
    throw new OutFileError(
      `--force isn't available on this system: pipegen can't replace ${show(target)} here without the risk of ` +
        'following a link to another file. Delete the old file first, or choose a new file name.',
    );
  }

  let writing = false; // set once the file may have been emptied or partly written
  try {
    let repo: BigIntStats;
    try {
      repo = await stat(resolve(cwd, opts.dir), { bigint: true }); // --dir may be your own link: its real folder
    } catch (e) {
      if (!isSystemError(e)) throw e;
      throw new OutFileError(`pipegen can't read the repo folder ${show(resolve(cwd, opts.dir))}: ${reason(e)}.`);
    }
    if (!repo.isDirectory()) throw new OutFileError(`The repo folder ${show(resolve(cwd, opts.dir))} is not a folder.`);

    const where = await resolveFolder(dirname(target), repo, refuse);
    const final = join(where.folder, basename(target));

    const pre = await lstatOrNull(final);
    if (pre?.isSymbolicLink()) refuse(SYMLINK);
    if (where.inRepo && !opts.force) {
      refuse(
        "it is inside the repo you are auditing. Don't write the report into the repo you're auditing: choose a " +
          'file outside it, or add --force to write it there anyway',
      );
    }
    const exists = posix
      ? 'the file already exists. Add --force to replace it, or choose a new file name'
      : 'the file already exists. Delete it first, or choose a new file name';
    if (pre !== null) {
      if (!posix || !opts.force) refuse(exists);
      if (!pre.isFile()) refuse(NOT_REGULAR);
      if (pre.nlink > 1n) refuse(HARD_LINKS);
    }

    const nonBlock = c.O_NONBLOCK ?? 0;
    const flags = !posix
      ? 'wx'
      : pre === null
        ? c.O_WRONLY | c.O_CREAT | c.O_EXCL | noFollow | nonBlock
        : c.O_WRONLY | noFollow | nonBlock;
    let fh: FileHandle;
    try {
      fh = await open(final, flags, MODE);
    } catch (e) {
      // Something appeared or changed between the checks and the open: say what it is now.
      const code = errCode(e);
      const now = await lstatOrNull(final).catch(() => null);
      if (code === 'EEXIST') refuse(now?.isSymbolicLink() ? SYMLINK : opts.force ? CHANGED : exists);
      if (code === 'ELOOP' || code === 'EMLINK' || code === 'EFTYPE') {
        refuse(now?.isSymbolicLink() ? SYMLINK : 'a folder on its path is a symbolic-link loop');
      }
      if (code === 'ENOENT' && pre !== null) refuse(CHANGED);
      if (code === 'ENXIO' || code === 'EISDIR') refuse(NOT_REGULAR);
      throw e;
    }

    try {
      const st = await fh.stat({ bigint: true });
      if (!st.isFile()) refuse(NOT_REGULAR);
      if (st.nlink > 1n) refuse(HARD_LINKS);
      if (pre !== null && !sameFile(st, pre)) refuse(CHANGED);
      await checkOpenedFolder(fh, where.id, refuse, pre === null);
      await fh.chmod(MODE);
      writing = true;
      if (pre !== null) await fh.truncate(0);
      await fh.writeFile(content, 'utf8');
    } finally {
      await fh.close();
    }
  } catch (e) {
    if (e instanceof OutFileError || !isSystemError(e)) throw e;
    const after = writing ? ' The file may be empty or incomplete.' : '';
    throw new OutFileError(`Couldn't write the report to ${show(target)}: ${reason(e)}.${after}`);
  }
}

interface ResolvedFolder {
  /** The real path of the target's folder (no links). */
  folder: string;
  /** Its identity, to compare with the folder the file really ends up in. */
  id: BigIntStats;
  /** It is the repo or a folder below it. */
  inRepo: boolean;
}

/**
 * Resolves the target's folder one part at a time (see the header). Refuses a missing folder, a part that is not
 * a folder, a link held by the repo or a folder below it, and too many links in a row. Other errors propagate.
 */
async function resolveFolder(lexical: string, repo: BigIntStats, refuse: (why: string) => never): Promise<ResolvedFolder> {
  const isRepoOrBelow = async (real: string): Promise<boolean> => {
    for (let p = real; ; p = dirname(p)) {
      if (sameFile(await stat(p, { bigint: true }), repo)) return true;
      if (dirname(p) === p) return false;
    }
  };

  let resolved = parse(lexical).root;
  const pending = splitParts(lexical.slice(resolved.length));
  let links = 0;
  while (pending.length > 0) {
    const part = pending.shift()!;
    if (part === '..') {
      resolved = dirname(resolved); // `resolved` has no links, so `..` is its real parent
      continue;
    }
    const next = join(resolved, part);
    let info: BigIntStats;
    try {
      info = await lstat(next, { bigint: true });
    } catch (e) {
      if (errCode(e) === 'ENOENT') refuse(`the folder ${show(next)} doesn't exist, and pipegen doesn't create folders`);
      throw e;
    }
    if (info.isSymbolicLink()) {
      if (await isRepoOrBelow(resolved)) {
        refuse(`the folder ${show(next)} inside the repo is a symbolic link, which could point outside the repo`);
      }
      if (++links > MAX_LINKS) refuse('the path to its folder has too many symbolic links in a row (probably a loop)');
      const link = await readlink(next);
      pending.unshift(...splitParts(isAbsolute(link) ? link.slice(parse(link).root.length) : link));
      if (isAbsolute(link)) resolved = parse(link).root;
      continue;
    }
    if (!info.isDirectory()) refuse(`${show(next)} is not a folder`);
    resolved = next;
  }
  return { folder: resolved, id: await lstat(resolved, { bigint: true }), inRepo: await isRepoOrBelow(resolved) };
}

/**
 * Linux: the folder the opened file is really in must be the folder that was checked (the same dev/ino). A parent
 * swapped for a link after the checks fails here, before anything is written. Where /proc can't tell (other
 * systems, no /proc), the exclusive create and the dev/ino match already keep any existing file safe.
 */
async function checkOpenedFolder(fh: FileHandle, folder: BigIntStats, refuse: (why: string) => never, created: boolean): Promise<void> {
  let actual: string;
  try {
    actual = await readlink(`/proc/self/fd/${fh.fd}`);
  } catch {
    return;
  }
  if (!isAbsolute(actual)) return; // not a path (e.g. "anon_inode:..."): nothing to compare
  const real = await lstat(dirname(actual), { bigint: true }).catch(() => null);
  if (real !== null && sameFile(real, folder)) return;
  refuse(
    'a folder on its path changed while pipegen was writing the report. Nothing was written' +
      (created ? `; an empty file may have been left at ${show(actual)}` : ''),
  );
}
