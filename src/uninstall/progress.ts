// v0.2 Plan V V5 (rulings V-B2, V-S10): the uninstall progress file, so a half-done uninstall can be finished. One per app repo, beside the
// local record file: `~/.config/pipegen/records/<owner>__<repo>.uninstall.json` (XDG_CONFIG_HOME when set), 0600, in the same trusted folder
// (prepareTrustedDir), written the way the local record file is (a fresh exclusive temp file, never through a link, fsynced, renamed).
//
// It holds where the uninstall is (`phase`), the plan's anchors, the uninstall pull request (number and URL), what was done and what was left,
// names and ids only: never a value, never an answer or a typed name (run 2 is a fresh plan; V4-R1 condition 3). A file pipegen can't read
// (not a plain file, too large, not its form, another repo's) stops the run and names it; it is never overwritten.
import { closeSync, constants, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import { z } from 'zod';
import type { RepoRef } from '../deliver/git-data.js';
import { localRecordPath, type LocalRecordDeps } from '../deliver/record.js';
import { safeText } from '../util/safe-text.js';
import { prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { UninstallError } from './errors.js';

/**
 * A: run 1 begun (re-run: phase A again, re-planned). A-done: run 1 finished; the next run reads the uninstall PR from GitHub. B: run 2 begun
 * (V6's).
 */
export type UninstallStage = 'A' | 'A-done' | 'B';
export interface ProgressItem { what: string; why: string; manual?: string }
export interface UninstallProgress {
  version: 1;
  /** GitHub's id of the app repo: a file of another repo of the same name is never used. */
  repoId: number;
  phase: UninstallStage;
  /** The anchors of the plan run 1 applied (V-S9). */
  anchors: { appHead: string; appTree: string; centralHead: string; recordBlobSha: string };
  /** The uninstall pull request run 1 opened (absent: none was needed, or it wasn't opened). */
  prNumber?: number; prUrl?: string;
  /** Run 1 found the install unfinished (no workflow of pipegen's live): no pull request to wait for. */
  unfinished?: true;
  /** The commit pipegen last set `pipegen/uninstall` to (V5-R1 sec M2): a re-run moves the branch only while it still points there. */
  uninstallHead?: string;
  /** The commit pipegen last set the central `pipegen/uninstall-<name>` to (V6-R1 sec M1): run 2 moves it only while it still points there. */
  centralUninstallHead?: string;
  /** V6-R3 sec M1: GitHub's id of `<owner>/pipelines`, saved right before pipegen sent its repo DELETE (cleared when GitHub refused it). */
  centralDeleteSent?: number;
  /** Run 1 needed no pull request and these workflows of pipegen's stay because the user kept them (V5-R1 sec M4): the next run's check
   *  for a live pipegen workflow passes them over (the run-2 preview still warns). */
  keptWorkflows?: string[];
  done: string[];
  leftovers: ProgressItem[];
  updatedAt: string;
}

/** The largest progress file pipegen reads. */
export const MAX_PROGRESS_BYTES = 512 * 1024;
const SHA = z.string().regex(/^[0-9a-f]{40}$/);
const TEXT = z.string().max(600);
const ITEM = z.strictObject({ what: TEXT, why: TEXT, manual: TEXT.optional() });
const PROGRESS = z.strictObject({
  version: z.literal(1), repoId: z.number().int().positive(), phase: z.enum(['A', 'A-done', 'B']),
  anchors: z.strictObject({ appHead: SHA, appTree: SHA, centralHead: SHA, recordBlobSha: SHA }),
  prNumber: z.number().int().positive().optional(), prUrl: z.string().max(300).regex(/^https:\/\/[^\s]*$/).optional(),
  unfinished: z.literal(true).optional(),
  uninstallHead: SHA.optional(),
  centralUninstallHead: SHA.optional(),
  centralDeleteSent: z.number().int().positive().optional(),
  keptWorkflows: z.array(z.string().max(300).regex(/^\.github\/workflows\/[^/]+\.ya?ml$/)).max(200).optional(),
  done: z.array(TEXT).max(2000), leftovers: z.array(ITEM).max(2000), updatedAt: z.string().max(40),
});

const KIND: TrustedDirKind = {
  noun: 'uninstall progress', keeping: 'where an uninstall stopped', risk: 'change what `pipegen uninstall` does next',
  error: (message, cause) => new UninstallError(message, cause === undefined ? undefined : { cause }),
};
const text = (s: string): string => safeText(String(s), 600);

/** Where the progress file of an app is (the path only; nothing is created). */
export function uninstallProgressPath(app: RepoRef, deps: LocalRecordDeps = {}): string {
  const record = localRecordPath(app, deps);
  return join(dirname(record), basename(record).replace(/\.json$/, '.uninstall.json'));
}

/** The progress file of one app repo: open() prepares the trusted folder and reads it; save() and remove() are synchronous. */
export class ProgressFile {
  readonly path: string;
  readonly #repoId: number;
  #state: UninstallProgress | null;

  private constructor(path: string, repoId: number, state: UninstallProgress | null) {
    this.path = path;
    this.#repoId = repoId;
    this.#state = state;
  }

  /** Prepares the records folder (0700, trusted chain) and reads the file. Unreadable, or another repo's: UninstallError naming it. */
  static async open(app: RepoRef, repoId: number, deps: LocalRecordDeps = {}): Promise<ProgressFile> {
    const file = uninstallProgressPath(app, deps);
    const uid = deps.uid ?? process.getuid?.();
    if (uid === undefined) throw new UninstallError('pipegen could not tell which user it runs as, so it keeps no uninstall progress file; nothing was changed.');
    const root = dirname(dirname(dirname(file)));
    const dir = await prepareTrustedDir(root, ['pipegen', 'records'], false, uid, KIND);
    const path = join(dir, basename(file));
    return new ProgressFile(path, repoId, readProgress(path, repoId));
  }

  /** The saved progress (null: none). */
  get state(): Readonly<UninstallProgress> | null { return this.#state; }

  /** Writes `p` (checked, names made safe) before it returns. */
  save(p: Omit<UninstallProgress, 'version' | 'repoId' | 'updatedAt'>): void {
    const value: UninstallProgress = PROGRESS.parse({
      version: 1, repoId: this.#repoId, phase: p.phase, anchors: { ...p.anchors },
      ...(p.prNumber === undefined ? {} : { prNumber: p.prNumber }), ...(p.prUrl === undefined || p.prUrl === '' ? {} : { prUrl: p.prUrl }),
      ...(p.unfinished === true ? { unfinished: true } : {}),
      ...(p.uninstallHead === undefined ? {} : { uninstallHead: p.uninstallHead }),
      ...(p.centralUninstallHead === undefined ? {} : { centralUninstallHead: p.centralUninstallHead }),
      ...(p.centralDeleteSent === undefined ? {} : { centralDeleteSent: p.centralDeleteSent }),
      ...(p.keptWorkflows === undefined || p.keptWorkflows.length === 0 ? {} : { keptWorkflows: [...p.keptWorkflows] }),
      done: p.done.slice(-2000).map(text),
      leftovers: p.leftovers.slice(-2000).map((x) => ({ what: text(x.what), why: text(x.why), ...(x.manual === undefined ? {} : { manual: text(x.manual) }) })),
      updatedAt: new Date().toISOString(),
    }) as UninstallProgress;
    const json = `${JSON.stringify(value, null, 1)}\n`;
    if (Buffer.byteLength(json) > MAX_PROGRESS_BYTES) throw new UninstallError(`pipegen didn't save its uninstall progress in ${this.path}: it is larger than pipegen's limit.`);
    const tmp = join(dirname(this.path), `.${basename(this.path)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
    let fd: number | null = null;
    try {
      fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const buf = Buffer.from(json, 'utf8');
      let off = 0;
      while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
      fsyncSync(fd);
      closeSync(fd);
      fd = null;
      renameSync(tmp, this.path);
    } catch (e) {
      if (fd !== null) try { closeSync(fd); } catch { /* closed */ }
      try { unlinkSync(tmp); } catch { /* gone */ }
      throw new UninstallError(`pipegen couldn't save its uninstall progress in ${this.path}.`, { cause: e });
    }
    this.#state = value;
  }

  /** Removes the file (nothing left to resume). */
  remove(): void {
    try { unlinkSync(this.path); } catch (e) {
      if ((e as { code?: unknown } | null)?.code !== 'ENOENT') throw new UninstallError(`pipegen couldn't remove ${this.path}.`, { cause: e });
    }
    this.#state = null;
  }
}

/** The progress file at `path`, null when there is none; anything pipegen can't read: a stop that names it (never overwritten). */
function readProgress(path: string, repoId: number): UninstallProgress | null {
  const stop = (why: string, cause?: unknown): never => {
    throw new UninstallError(`pipegen can't use its uninstall progress file ${path}: ${why}. pipegen won't guess what the last uninstall did, and it doesn't overwrite that file: check it, move it away, then run \`npx pipegen uninstall\` again. Nothing was changed.`, cause === undefined ? undefined : { cause });
  };
  let info;
  try { info = lstatSync(path); } catch (e) {
    if ((e as { code?: unknown } | null)?.code === 'ENOENT') return null;
    return stop('it could not be checked', e);
  }
  if (!info.isFile()) return stop('it is not a plain file');
  if (info.size > MAX_PROGRESS_BYTES) return stop('it is larger than pipegen\'s limit');
  let data: unknown;
  try { data = JSON.parse(readFileSync(path, 'utf8')); } catch (e) { return stop('it is not JSON', e); }
  const r = PROGRESS.safeParse(data);
  if (!r.success) return stop('it is not in pipegen\'s form');
  if (r.data.repoId !== repoId) return stop('it belongs to another repo of the same name (another GitHub id)');
  return r.data as UninstallProgress;
}
