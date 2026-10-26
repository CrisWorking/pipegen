// Memory of proven tools (Plan B Task 5): which tools passed proof runs, for which need category and language,
// so a later run tries them first. A local file in the user's own folder, never in the repo.
//
// - Where: $XDG_CONFIG_HOME/pipegen/memory.json or ~/.config/pipegen/memory.json (the brief's location). The folder
//   is created 0700 and every directory above it is checked like the tool cache is (src/util/trusted-dir.ts), so
//   nothing else can write there.
// - Reading: no-follow open, at most 1 MB, strict zod schema. A missing, unsafe, oversized or corrupt store gives
//   an empty memory plus a note. It is never trusted partially and never crashes a run. Bundled data/memory.json
//   (found with packageDataPath, ruling S2) is read the same way and the user's file overrides it per entry.
// - Writing (save): re-check the folder, refuse a symlink at the target, write a fresh temp file (0600,
//   exclusive, no-follow) and rename it into place.
// - Never a secret (ruling S33): `record` derives the category from NEED_ID_CATEGORY and refuses the whole spec if
//   any string in it looks like a secret (findSecretLike or redact would change it). `secrets` holds names only.
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { z } from 'zod';
import { findSecretLike, redact } from '../ai/redact.js';
import type { Candidate, Language, StepSpec } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { checkChain, checkDir, prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { NEED_ID_CATEGORY } from './needs.js';

export interface MemoryEntry { category: string; language: Language | 'any'; spec: StepSpec; provenAt: string; proofs: number; lastFailureAt?: string }
export interface MemoryStore {
  lookup(category: string, language: Language): MemoryEntry[];
  record(spec: StepSpec, language: Language, outcome: 'proven' | 'failed', at: Date): void;
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
  /**
   * The commands a reviewed tool is known to run (from its reviewed step template). A remembered `cli.command` must
   * be one of them: a hostile repo must not plant a command that a later run reuses. Task 8's reviewed list is not
   * wired yet, so by default nothing is known and no spec with a `cli` is remembered.
   */
  reviewedCommands?: (tool: Candidate) => string[][];
}

export class MemoryError extends Error {}

export const MAX_MEMORY_BYTES = 1_000_000;
const MAX_ENTRIES = 2_000;
const LANGUAGES = ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php', 'other'] as const;

const KIND: TrustedDirKind = {
  noun: 'memory', keeping: 'its memory of proven tools', risk: 'change which tools pipegen tries first',
  error: (message, cause) => new MemoryError(message, cause === undefined ? undefined : { cause }),
};

const str = (max: number) => z.string().max(max);
const strMap = z.record(str(200), str(1000)).refine((m) => Object.keys(m).length <= 50);
const when = str(40).refine((s) => !Number.isNaN(Date.parse(s)), 'not a date');

const statsSchema = z.strictObject({
  repo: str(200), stars: z.number(), archived: z.boolean(), lastReleaseAt: when.nullable(), scorecard: z.number().nullable(),
  scorecardAt: when.nullable(), verifiedPublisher: z.boolean(), license: str(100).nullable(), advisories: z.number().nullable(),
});
const candidateSchema = z.strictObject({
  id: str(100), name: str(200), kind: z.enum(['action', 'cli', 'docker']), repo: str(200), version: str(100),
  pin: z.strictObject({ sha: str(200).optional(), checksum: str(200).optional(), digest: str(200).optional() }),
  source: z.enum(['reviewed', 'discovery', 'memory']), reviewed: z.boolean(), stats: statsSchema.optional(),
  categories: z.array(str(100)).max(30),
});
const installSchema = z.strictObject({
  method: z.enum(['npm', 'pip', 'github-release', 'docker']), package: str(300), version: str(100),
  checksum: str(200).optional(), digest: str(200).optional(),
});
const specSchema = z.strictObject({
  needId: str(100), tool: candidateSchema,
  action: z.strictObject({ uses: str(300), with: strMap }).optional(),
  cli: z.strictObject({ install: installSchema, command: z.array(str(1000)).max(100), env: strMap.optional() }).optional(),
  output: z.strictObject({ path: str(500), format: z.enum(['sarif', 'junit', 'zap-json', 'none']) }),
  workingDir: str(500).optional(),
  needsServices: z.array(z.enum(['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq', 'external'])).max(10).optional(),
  secrets: z.array(str(100)).max(50).optional(),
});
const entrySchema = z.strictObject({
  category: str(100), language: z.enum([...LANGUAGES, 'any']), spec: specSchema,
  provenAt: when, proofs: z.number().int().min(0).max(1_000_000), lastFailureAt: when.optional(),
});
const storeSchema = z.array(entrySchema).max(MAX_ENTRIES);

const errCode = (e: unknown) => (e as { code?: unknown } | null)?.code;
const keyOf = (e: { category: string; language: string; spec: { tool: { repo: string } } }) => `${e.category}|${e.language}|${e.spec.tool.repo}`;

/** The same entry seen by two runs: the one with more proofs (then the newer proof) wins; the later failure is kept. */
function mergeEntries(a: MemoryEntry, b: MemoryEntry): MemoryEntry {
  const aWins = a.proofs !== b.proofs ? a.proofs > b.proofs : Date.parse(a.provenAt) >= Date.parse(b.provenAt);
  const win = structuredClone(aWins ? a : b);
  const fails = [a.lastFailureAt, b.lastFailureAt].filter((x): x is string => x !== undefined);
  if (fails.length > 0) win.lastFailureAt = fails.reduce((x, y) => (Date.parse(x) >= Date.parse(y) ? x : y));
  return win;
}

/** Every string in a value (keys excluded), for the secret check. */
function* strings(v: unknown): Generator<string> {
  if (typeof v === 'string') yield v;
  else if (Array.isArray(v)) for (const x of v) yield* strings(x);
  else if (v !== null && typeof v === 'object') for (const [k, x] of Object.entries(v)) { yield k; yield* strings(x); } // keys too (ruling M2)
}
const looksSecret = (s: string) => findSecretLike(s).length > 0 || redact(s) !== s;
const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,99}$/;

const CONTROL_RE = /[\u0000-\u001f\u007f]/;
/** A plain relative path: no `..`, not absolute (POSIX or drive letter), no backslash or control character, 1-200 chars. */
function plainRelativePath(p: string): boolean {
  if (p === '' || p.length > 200 || CONTROL_RE.test(p) || p.includes('\\') || p.startsWith('/') || /^[A-Za-z]:/.test(p)) return false;
  return !p.split('/').includes('..');
}
type KnownCommands = (tool: Candidate) => string[][];
const sameCommand = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Why a spec may not be stored, or null. Checks every string (and key), `secrets` must be plain variable names,
 * `output.path` a plain relative path, `workingDir` is never kept (see `forget`), and a `cli.command` must be one
 * of the reviewed tool's known commands.
 */
function refusal(spec: StepSpec, known: KnownCommands): string | null {
  if (!Object.hasOwn(NEED_ID_CATEGORY, spec.needId)) return `"${safeText(spec.needId, 40)}" is not a need pipegen knows`;
  for (const n of spec.secrets ?? []) if (!SECRET_NAME_RE.test(n)) return 'a secret was listed by something other than its name';
  for (const s of strings(spec)) if (looksSecret(s)) return 'it contains a value that looks like a secret';
  if (!plainRelativePath(spec.output.path)) return 'its output path is not a plain relative path';
  if (spec.workingDir !== undefined) return 'it names a working directory, which belongs to one repo';
  if (spec.cli !== undefined && !known(spec.tool).some((c) => sameCommand(c, spec.cli!.command))) return "its command is not one of the reviewed tool's known commands";
  return null;
}

/** The spec as it is remembered: nothing that belongs to the repo it was proven in. */
function forget(spec: StepSpec): StepSpec {
  const { workingDir: _repoSpecific, ...rest } = structuredClone(spec);
  return rest;
}

/** Entries of one memory file (bundled or the user's); `empty + note` on anything wrong. */
async function readStore(path: string, note: (m: string) => void, known: KnownCommands, uid?: number): Promise<MemoryEntry[] | 'missing'> {
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
    // nothing is trusted partially: one secret-looking value or unknown need drops the whole file
    const entries = parsed.data as MemoryEntry[];
    for (const e of entries) {
      const why = refusal(e.spec, known);
      if (why !== null) return bad(why);
      if (NEED_ID_CATEGORY[e.spec.needId as keyof typeof NEED_ID_CATEGORY] !== e.category) return bad('an entry has a category that does not match its need');
    }
    return entries;
  } catch {
    return bad('it could not be read');
  } finally {
    await fh.close();
  }
}

/** The entries shipped in data/memory.json, validated like the user's file (used by the bundle probe too). */
export async function loadBundledMemory(path: string = packageDataPath('memory.json'), reviewedCommands: KnownCommands = () => []): Promise<MemoryEntry[]> {
  const notes: string[] = [];
  const r = await readStore(path, (m) => notes.push(m), reviewedCommands);
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
  const known: KnownCommands = deps.reviewedCommands ?? (() => []);
  const merged = new Map<string, MemoryEntry>();
  const mine = new Set<string>(); // keys that belong in the user's file

  // bundled
  try {
    const b = await readStore(paths.bundled ?? packageDataPath('memory.json'), note, known);
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
      const u = await readStore(join(folder, name), note, known, uid);
      if (u !== 'missing') for (const e of u) { merged.set(keyOf(e), e); mine.add(keyOf(e)); }
    }
  } catch (e) {
    note(`pipegen ignored its memory of proven tools: ${safeText(e instanceof Error ? e.message : String(e), 250)}`);
  }

  return {
    notes,
    lookup(category, language) {
      return [...merged.values()]
        .filter((e) => e.category === category && (e.language === language || e.language === 'any'))
        .filter((e) => !(e.lastFailureAt !== undefined && Date.parse(e.lastFailureAt) > Date.parse(e.provenAt)))
        .sort((a, b) => b.proofs - a.proofs)
        .map((e) => structuredClone(e));
    },
    record(spec, language, outcome, at) {
      const clean = forget(spec);
      const why = refusal(clean, known);
      if (why !== null) { note(`pipegen did not remember ${safeText(spec.tool.repo, 80)}: ${why}.`); return; }
      const category = NEED_ID_CATEGORY[spec.needId as keyof typeof NEED_ID_CATEGORY];
      const stamp = at.toISOString();
      const key = keyOf({ category, language, spec });
      const old = merged.get(key);
      if (outcome === 'failed') {
        if (old === undefined) return; // nothing proven to hide
        merged.set(key, { ...old, lastFailureAt: stamp });
      } else {
        const next: MemoryEntry = { category, language, spec: clean, provenAt: stamp, proofs: (old?.proofs ?? 0) + 1 };
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
      const current = await readStore(target, note, known, uid);
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
