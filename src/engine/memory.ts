// Memory of proven tools (Plan B Task 5): which reviewed tools passed proof runs, for which need category and
// language, so a later run tries them first. A local file in the user's own folder, never in the repo.
//
// - It remembers ids, never steps (fix round 2): an entry is the reviewed tool's id (data/reviewed-tools.yml), the need
//   category, the language, a proof count and two dates. No spec, command, path or free text, so nothing planted
//   in the file can change what runs: the CALLER re-renders the step from the reviewed entry it finds by id.
// - Where: $XDG_CONFIG_HOME/pipegen/memory.json or ~/.config/pipegen/memory.json (the brief's location). The folder
//   is created 0700 and every directory above it is checked like the tool cache is (src/util/trusted-dir.ts), on
//   read as well as on write.
// - Reading: no-follow open, at most 1 MB, strict zod schema. A missing, unsafe, oversized, corrupt or old-format
//   (with a spec) store gives an empty memory plus a note. It is never trusted partially and never crashes a run.
//   Bundled data/memory.json (found with packageDataPath, ruling S2) is read the same way; the user's file wins.
// - Writing (save): re-check the folder, refuse a symlink at the target, re-read and merge what another run saved,
//   write a fresh temp file (0600, exclusive, no-follow) and rename it into place.
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { z } from 'zod';
import { NEED_CATEGORIES, type Language, type ReviewedTool } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { checkChain, checkDir, prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { NEED_ID_CATEGORY } from './needs.js';
import { ID_RE, loadReviewed } from './reviewed.js';

/** Everything memory remembers about a tool. `toolId` is a ReviewedTool id: callers re-render the step from the reviewed list. */
export interface MemoryEntry { toolId: string; needCategory: string; language: Language | 'any'; provenAt: string; proofs: number; lastFailureAt?: string }
export interface MemoryStore {
  lookup(category: string, language: Language): MemoryEntry[];
  /** `needId` is the need's id (its category is derived through NEED_ID_CATEGORY); `toolId` must be in the reviewed list. */
  record(toolId: string, needId: string, language: Language, outcome: 'proven' | 'failed', at: Date): void;
  save(): Promise<void>;
  /** Plain-English problems met while reading, recording or saving (empty when all went well). */
  readonly notes: string[];
}
export interface MemoryPaths { user?: string; bundled?: string }
export interface MemoryDeps {
  /** Read for XDG_CONFIG_HOME. Default: process.env. */
  env?: Record<string, string | undefined>;
  /** Default: os.homedir(). */
  home?: string;
  /** The user the folders must belong to. Default: process.getuid(). */
  uid?: number;
  /** The reviewed list `record` checks ids against. Default: loadReviewed() (read on the first `record`). */
  reviewed?: ReviewedTool[];
}

export class MemoryError extends Error {}

export const MAX_MEMORY_BYTES = 1_000_000;
const MAX_ENTRIES = 2_000;
const LANGUAGES = ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php', 'other'] as const;

const KIND: TrustedDirKind = {
  noun: 'memory', keeping: 'its memory of proven tools', risk: 'change which tools pipegen tries first',
  error: (message, cause) => new MemoryError(message, cause === undefined ? undefined : { cause }),
};

const when = z.string().max(40).refine((s) => !Number.isNaN(Date.parse(s)), 'not a date');
const entrySchema = z.strictObject({
  toolId: z.string().regex(ID_RE),
  needCategory: z.enum(NEED_CATEGORIES),
  language: z.enum([...LANGUAGES, 'any']),
  provenAt: when,
  proofs: z.number().int().min(0).max(1_000_000),
  lastFailureAt: when.optional(),
});
const storeSchema = z.array(entrySchema).max(MAX_ENTRIES);

const errCode = (e: unknown) => (e as { code?: unknown } | null)?.code;
const keyOf = (e: { needCategory: string; language: string; toolId: string }) => `${e.needCategory}|${e.language}|${e.toolId}`;

/** The same entry seen by two runs: the one with more proofs (then the newer proof) wins; the later failure is kept. */
function mergeEntries(a: MemoryEntry, b: MemoryEntry): MemoryEntry {
  const aWins = a.proofs !== b.proofs ? a.proofs > b.proofs : Date.parse(a.provenAt) >= Date.parse(b.provenAt);
  const win = { ...(aWins ? a : b) };
  const fails = [a.lastFailureAt, b.lastFailureAt].filter((x): x is string => x !== undefined);
  if (fails.length > 0) win.lastFailureAt = fails.reduce((x, y) => (Date.parse(x) >= Date.parse(y) ? x : y));
  return win;
}

/** Entries of one memory file (bundled or the user's); `empty + note` on anything wrong. */
async function readStore(path: string, note: (m: string) => void, uid?: number): Promise<MemoryEntry[] | 'missing'> {
  const bad = (why: string): MemoryEntry[] => {
    note(`pipegen ignored its memory of proven tools (${safeText(path, 120)}): ${why}.`);
    return [];
  };
  let fh;
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (e) {
    const code = (e as { code?: unknown } | null)?.code;
    if (code === 'ENOENT') return 'missing';
    return bad(code === 'ELOOP' ? 'it is a symbolic link' : 'it could not be opened safely');
  }
  try {
    const info = await fh.stat();
    if (!info.isFile()) return bad('it is not a regular file');
    if (uid !== undefined && info.uid !== uid) return bad('it is not owned by you');
    if (info.size > MAX_MEMORY_BYTES) return bad('it is too large');
    const buf = Buffer.alloc(MAX_MEMORY_BYTES + 1);
    let n = 0;
    for (;;) {
      const { bytesRead } = await fh.read(buf, n, buf.length - n, null);
      if (bytesRead === 0) break;
      n += bytesRead;
      if (n > MAX_MEMORY_BYTES) return bad('it is too large');
    }
    let json: unknown;
    try {
      json = JSON.parse(buf.subarray(0, n).toString('utf8'));
    } catch {
      return bad('it is not valid JSON');
    }
    const parsed = storeSchema.safeParse(json);
    if (!parsed.success) return bad('it does not have the shape pipegen writes');
    const entries = parsed.data as MemoryEntry[];
    return entries;
  } catch {
    return bad('it could not be read');
  } finally {
    await fh.close();
  }
}

/** The entries shipped in data/memory.json, validated like the user's file (used by the bundle probe too). */
export async function loadBundledMemory(path: string = packageDataPath('memory.json')): Promise<MemoryEntry[]> {
  const notes: string[] = [];
  const r = await readStore(path, (m) => notes.push(m));
  if (notes.length > 0) throw new MemoryError(notes[0]);
  return r === 'missing' ? [] : r;
}

/**
 * Opens the memory: bundled entries, then the user's file on top (same category + language + tool repo → the
 * user's entry wins). Never throws for a bad store; read `notes`. `paths.user` is a file path (its folder is
 * checked like the default one).
 */
export async function openMemory(paths: MemoryPaths = {}, deps: MemoryDeps = {}): Promise<MemoryStore> {
  const notes: string[] = [];
  const note = (m: string) => { if (!notes.includes(m)) notes.push(m); };
  let reviewedIds: Set<string> | null = null; // loaded on the first record
  const merged = new Map<string, MemoryEntry>();
  const mine = new Set<string>(); // keys that belong in the user's file

  // bundled
  try {
    const b = await readStore(paths.bundled ?? packageDataPath('memory.json'), note);
    if (b !== 'missing') for (const e of b) merged.set(keyOf(e), e);
  } catch (e) {
    note(`pipegen could not find its bundled memory of proven tools (${safeText(e instanceof Error ? e.message : String(e), 150)}).`);
  }

  // where the user's file lives
  const uid = deps.uid ?? process.getuid?.();
  const env = deps.env ?? process.env;
  const xdg = env.XDG_CONFIG_HOME;
  const base = xdg !== undefined && isAbsolute(xdg) ? xdg : join(deps.home ?? homedir(), '.config');
  const file = paths.user ?? join(base, 'pipegen', 'memory.json');
  const dir = dirname(file);
  const name = basename(file);

  /** Creates (if needed) and checks the folder; returns the memory file's real path. */
  const prepare = async (): Promise<string> => {
    if (uid === undefined) throw new MemoryError('pipegen could not tell which user it runs as, so it will not keep its memory of proven tools.');
    const real = paths.user !== undefined ? await prepareTrustedDir(dir, [], true, uid, KIND) : await prepareTrustedDir(base, ['pipegen'], false, uid, KIND);
    return join(real, name);
  };

  /**
   * The folder's real path if it exists and passes the same trust walk as a write (nothing is created), null when it
   * does not exist yet. Anything else throws a MemoryError.
   */
  const trustedFolder = async (): Promise<string | null> => {
    if (uid === undefined) throw new MemoryError('pipegen could not tell which user it runs as.');
    const ownLevel = paths.user === undefined ? join(base, 'pipegen') : dir;
    const above = paths.user === undefined ? base : dirname(dir);
    let realAbove: string;
    try {
      realAbove = await realpath(above);
    } catch (e) {
      if (errCode(e) === 'ENOENT' || errCode(e) === 'ENOTDIR') return null;
      throw new MemoryError(`Couldn't resolve ${above}.`, { cause: e });
    }
    await checkChain(realAbove, uid, false, KIND);
    const level = join(realAbove, basename(ownLevel));
    try {
      await lstat(level);
    } catch (e) {
      if (errCode(e) === 'ENOENT') return null;
      throw new MemoryError(`Couldn't check ${level}.`, { cause: e });
    }
    await checkDir(level, uid, true, KIND);
    return level;
  };

  // the user's file
  try {
    const folder = await trustedFolder();
    if (folder !== null) {
      const u = await readStore(join(folder, name), note, uid);
      if (u !== 'missing') for (const e of u) { merged.set(keyOf(e), e); mine.add(keyOf(e)); }
    }
  } catch (e) {
    note(`pipegen ignored its memory of proven tools: ${safeText(e instanceof Error ? e.message : String(e), 250)}`);
  }

  return {
    notes,
    lookup(category, language) {
      return [...merged.values()]
        .filter((e) => e.needCategory === category && (e.language === language || e.language === 'any'))
        .filter((e) => !(e.lastFailureAt !== undefined && Date.parse(e.lastFailureAt) > Date.parse(e.provenAt)))
        .sort((a, b) => b.proofs - a.proofs)
        .map((e) => ({ ...e }));
    },
    record(toolId, needId, language, outcome, at) {
      if (reviewedIds === null) {
        try {
          reviewedIds = new Set((deps.reviewed ?? loadReviewed()).map((t) => t.id));
        } catch (e) {
          note(`pipegen could not load its reviewed tool list, so it remembered nothing (${safeText(e instanceof Error ? e.message : String(e), 150)}).`);
          return;
        }
      }
      if (!ID_RE.test(toolId) || !reviewedIds.has(toolId)) { note(`pipegen did not remember "${safeText(toolId, 40)}": it is not a reviewed tool.`); return; }
      if (!Object.hasOwn(NEED_ID_CATEGORY, needId)) { note(`pipegen did not remember ${toolId}: "${safeText(needId, 40)}" is not a need it knows.`); return; }
      const needCategory = NEED_ID_CATEGORY[needId as keyof typeof NEED_ID_CATEGORY];
      const stamp = at.toISOString();
      const key = keyOf({ needCategory, language, toolId });
      const old = merged.get(key);
      if (outcome === 'failed') {
        if (old === undefined) return; // nothing proven to hide
        merged.set(key, { ...old, lastFailureAt: stamp });
      } else {
        const next: MemoryEntry = { toolId, needCategory, language, provenAt: stamp, proofs: (old?.proofs ?? 0) + 1 };
        if (old?.lastFailureAt !== undefined) next.lastFailureAt = old.lastFailureAt;
        merged.set(key, next);
      }
      mine.add(key);
    },
    async save() {
      const target = await prepare();
      const info = await lstat(target).catch(() => null);
      if (info !== null && !info.isFile()) throw new MemoryError(`pipegen won't write its memory through ${target}: it is a symbolic link or not a regular file.`);
      // Another run may have saved since we opened: re-read the file (same trusted read) and merge, so two runs
      // saving different entries keep both. Same key: more proofs win (then the newer proof); a failure either saw stays.
      const current = await readStore(target, note, uid);
      if (current !== 'missing') {
        for (const e of current) {
          const k = keyOf(e);
          const ours = merged.get(k);
          merged.set(k, ours === undefined || !mine.has(k) ? e : mergeEntries(ours, e));
          mine.add(k);
        }
      }
      const entries = [...mine].map((k) => merged.get(k) as MemoryEntry);
      const tmp = join(dirname(target), `.memory-${randomBytes(8).toString('hex')}.tmp`);
      const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        await fh.writeFile(JSON.stringify(entries, null, 2) + '\n');
        await fh.close();
        await rename(tmp, target);
      } catch (e) {
        await fh.close().catch(() => {});
        await unlink(tmp).catch(() => {});
        throw e;
      }
    },
  };
}
