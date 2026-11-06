// `pipegen hook secrets` (v0.2 Plan G, G6: the secrets-hook carry; rulings G6-R-sec1, G6-R2). The command pipegen's local secrets hook runs
// at every commit (src/engine/created-builders.ts secretsHookRun: `npx --yes --prefix=/ --registry=https://registry.npmjs.org pipegen@<exact>
// hook secrets`).
//
// What is scanned: what is about to be committed. At the repository's top folder (`git rev-parse --show-toplevel`, so a run from a sub-folder
// sees the whole index, G6-R2 spec I1), one `git diff --cached --raw -z --no-renames --diff-filter=d --no-abbrev` lists every staged change
// but a deletion, with its new mode and blob id: regular files (100644, 100755) and symbolic links (120000: the link's target text is
// committed, so it is scanned as a plain file, G6-R2 M6); submodules (160000) hold nothing of this repository. Each blob's RAW bytes are read
// with `git cat-file --batch` (no .gitattributes filter, eol, ident or working-tree-encoding applies, G6-R-sec1; GIT_NO_REPLACE_OBJECTS=1, so a
// refs/replace object can't stand in for the staged one, G6-R2 M5) and written into a private temp folder.
//
// How (G6-R2 C1): the export is staged exactly as the gate stages a checkout in CI (gate/src/stage.ts stageWorkspace): each file under a
// neutral name `fNNNNNNNN` plus the pinned path rules' suffix (so neither the default path allowlist, which skips package-lock.json, *.svg,
// node_modules/, an unanchored gitleaks.toml, …, nor a staged .gitleaksignore applies), written after a prefix line (so no magic number
// makes the scanner skip it as an archive) and followed by a fresh canary. pipegen's PINNED gitleaks (ensurePinnedBinary re-hashes it before
// every use) scans the stage folder with the reviewed config (it holds the canary rule; never the repository's .gitleaks.toml, nor
// GITLEAKS_CONFIG), inline allow comments ignored, the secret redacted, a SARIF report into the private folder. The gate's own reader
// (parseSarifText, readStage, applyStage) maps the findings back to the index paths and turns every staged file whose canary was not
// reported exactly once into a not-scanned finding. Any finding blocks the commit (exit 1); a scan that can't run blocks it too (exit 2).
// The private folder is removed at the end, on SIGINT and SIGTERM, and this user's stale ones are swept at the start (G6-R2 M7). No shell.
import { spawn } from 'node:child_process';
import { chmodSync, lstatSync, readdirSync, rmSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { STAGED_NAME_RE, applyStage, readStage, stageWorkspace, STAGE_FILES_DIR, NOT_SCANNED_RULE, StageError } from '../../gate/src/stage.js';
import { parseSarifText } from '../../gate/src/sarif.js';
import { ensurePinnedBinary } from '../engine/linters.js';
import { SECRETS_SCAN_CONFIG } from '../engine/tool-flags.js';
import { safeText } from '../util/safe-text.js';
import type { CliIO } from './io.js';

/** The scanner's exit codes with `--exit-code 10`: nothing found, and found (every scanned file reports its canary, so a full scan finds). */
export const HOOK_SECRETS_EXIT = Object.freeze({ clean: 0, found: 10 });
/** The SARIF report's name in the private folder. */
export const HOOK_REPORT = 'report.sarif';
/** The private folders' name prefix (swept when stale). */
export const HOOK_TMP_PREFIX = 'pipegen-hook-';
/** A private folder older than this is from a run that died; it is removed at the start of the next run. */
const STALE_MS = 15 * 60_000;
/** The staged blobs are read in one answer of at most this many bytes. */
export const MAX_STAGED_BLOB_BYTES = 512 * 1024 * 1024;

/** The fixed scanner argv: only the config file, the (empty) ignore folder and the report path change; it scans its working folder. Log level error: its own "leaks found" count holds the canaries, so pipegen prints the findings itself. */
export function hookSecretsArgv(config: string, ignoreDir: string, report: string): string[] {
  return [
    'dir', '--no-banner', '--redact', '--no-color', '--ignore-gitleaks-allow', '--config', config, '--gitleaks-ignore-path', ignoreDir,
    '--report-format', 'sarif', '--report-path', report, '--exit-code', String(HOOK_SECRETS_EXIT.found), '--max-archive-depth', '0', '--log-level', 'error', '.',
  ];
}

export interface HookSecretsDeps {
  /** The pinned gitleaks' absolute path, checked just now. Default: ensurePinnedBinary('gitleaks'). */
  gitleaks?: () => Promise<string>;
  /** Runs the scanner without a shell; resolves to its exit code (-1: stopped by a signal). Default: child_process.spawn. */
  exec?: (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }) => Promise<number>;
  /** Runs git without a shell in `cwd` (stdin from `input`); resolves to its exit code and stdout. Default: child_process.spawn of `git`. */
  git?: (args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; input?: Buffer }) => Promise<{ code: number; stdout: Buffer }>;
  /** Default: Date.now (the stale-folder sweep). */
  now?: () => number;
}

const spawnExec = (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): Promise<number> => new Promise((resolve, reject) => {
  const child = spawn(file, args, { cwd: opts.cwd, env: opts.env, stdio: ['ignore', 'inherit', 'inherit'], shell: false });
  child.on('error', reject);
  child.on('close', (code) => { resolve(code ?? -1); });
});
/** The answer was larger than MAX_STAGED_BLOB_BYTES. */
const TOO_LARGE = -2;
const spawnGit = (args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; input?: Buffer }): Promise<{ code: number; stdout: Buffer }> => new Promise((resolve, reject) => {
  const child = spawn('git', args, { cwd: opts.cwd, env: opts.env, stdio: [opts.input === undefined ? 'ignore' : 'pipe', 'pipe', 'ignore'], shell: false });
  const chunks: Buffer[] = [];
  let size = 0;
  child.on('error', reject);
  child.stdout?.on('data', (c: Buffer) => { size += c.length; if (size > MAX_STAGED_BLOB_BYTES) child.kill(); else chunks.push(c); });
  child.on('close', (code) => { resolve({ code: size > MAX_STAGED_BLOB_BYTES ? TOO_LARGE : code ?? -1, stdout: Buffer.concat(chunks) }); });
  // a git that exits before reading its input gives EPIPE here; its exit code tells what happened
  child.stdin?.on('error', () => {});
  if (opts.input !== undefined) child.stdin?.end(opts.input);
});

/** A plain-English refusal: the commit is blocked with this message (exit 2). */
class HookError extends Error {}

/** One staged change to scan: its index path (raw bytes) and blob id. */
interface StagedBlob { path: Buffer; oid: string }
/** The modes scanned: regular files, and links (their target text is committed). */
const SCANNED_MODES: ReadonlySet<string> = new Set(['100644', '100755', '120000']);

/**
 * The staged changes from ONE `git diff --cached --raw -z` at the top folder: `:<old> <new> <oldid> <newid> <status>\0<path>\0` per change.
 * A record of another shape, a mode pipegen does not know, or a wanted change none of whose records could be read fails closed.
 */
async function stagedBlobs(git: NonNullable<HookSecretsDeps['git']>, top: string, env: NodeJS.ProcessEnv): Promise<StagedBlob[]> {
  const r = await git(['diff', '--cached', '--raw', '-z', '--no-renames', '--diff-filter=d', '--no-abbrev'], { cwd: top, env });
  if (r.code === TOO_LARGE) throw new HookError('the list of staged changes is larger than pipegen reads.');
  if (r.code !== 0) throw new HookError('git could not list the staged changes.');
  const parts = splitNul(r.stdout);
  const out: StagedBlob[] = [];
  for (let i = 0; i < parts.length; i += 2) {
    const head = /^:(\d{6}) (\d{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) ([ACMRTU])$/.exec(parts[i]?.toString('latin1') ?? '');
    const path = parts[i + 1];
    if (head === null || path === undefined || path.length === 0) throw new HookError('git listed a staged change pipegen can not read, so it can not tell what is committed.');
    const mode = head[2] as string;
    if (mode === '160000') continue;   // a submodule: its files are another repository's
    if (!SCANNED_MODES.has(mode)) throw new HookError(`a staged change has the mode ${mode}, which pipegen does not scan.`);
    out.push({ path, oid: head[4] as string });
  }
  return out;
}
const splitNul = (b: Buffer): Buffer[] => {
  const out: Buffer[] = [];
  let at = 0;
  while (at < b.length) {
    const nul = b.indexOf(0, at);
    if (nul < 0) { out.push(b.subarray(at)); break; }
    out.push(b.subarray(at, nul));
    at = nul + 1;
  }
  return out;
};

/** A plain relative index path (no empty, `.` or `..` segment, no backslash), so the file lands inside the export folder. */
const safeIndexPath = (p: Buffer): boolean => p.length > 0 && p.length <= 4096 && p[0] !== 0x2f && !p.includes(0x5c) && p.toString('latin1').split('/').every((s) => s !== '' && s !== '.' && s !== '..');

/**
 * Writes each blob's RAW bytes (`git cat-file --batch`) under `dir` at its index path, mode 0600, creating only folders of its own inside the
 * private folder (nothing there is a link), never overwriting: two staged paths that are one name on this disk (letter case) fail plainly.
 */
async function exportBlobs(git: NonNullable<HookSecretsDeps['git']>, top: string, env: NodeJS.ProcessEnv, dir: string, blobs: readonly StagedBlob[]): Promise<void> {
  for (const b of blobs) if (!safeIndexPath(b.path)) throw new HookError('a staged path is not a plain relative path, so pipegen can not export it to scan.');
  const r = await git(['cat-file', '--batch'], { cwd: top, env, input: Buffer.from(blobs.map((b) => `${b.oid}\n`).join(''), 'utf8') });
  if (r.code === TOO_LARGE) throw new HookError(`the staged files are larger than ${MAX_STAGED_BLOB_BYTES / 1024 / 1024} MiB in all, more than pipegen's local scan reads; commit them in smaller parts (CI still scans everything).`);
  if (r.code !== 0) throw new HookError('git could not read the staged files.');
  const buf = r.stdout;
  let at = 0;
  const bad = (): never => { throw new HookError('git gave an unreadable answer for the staged files.'); };
  for (const b of blobs) {
    const nl = buf.indexOf(0x0a, at);
    if (nl < 0) bad();
    const head = /^([0-9a-f]{40}|[0-9a-f]{64}) blob (\d{1,12})$/.exec(buf.subarray(at, nl).toString('utf8'));
    if (head === null || head[1] !== b.oid) bad();
    const size = Number((head as RegExpExecArray)[2]);
    const start = nl + 1;
    if (start + size + 1 > buf.length || buf[start + size] !== 0x0a) bad();
    const target = Buffer.concat([Buffer.from(`${dir}/`), b.path]);
    try {
      await mkdir(Buffer.from(target.subarray(0, target.lastIndexOf(0x2f))), { recursive: true, mode: 0o700 });
      await writeFile(target, buf.subarray(start, start + size), { mode: 0o600, flag: 'wx' });
    } catch (e) {
      const code = (e as { code?: unknown }).code;
      if (code === 'EEXIST' || code === 'ENOTDIR' || code === 'EISDIR') throw new HookError('two staged paths are the same name on this disk (they differ only in letter case, or one is the folder of the other), so pipegen can not scan both; rename one.');
      throw e;
    }
    at = start + size + 1;
  }
  if (at !== buf.length) bad();
}

/** Makes a folder tree writable again (the stage folder is read-only) and removes it; never follows a link. */
function removeTree(dir: string): void {
  const fix = (d: string): void => {
    const st = lstatSync(d, { throwIfNoEntry: false });
    if (st === undefined || st.isSymbolicLink() || !st.isDirectory()) return;
    try { chmodSync(d, 0o700); } catch { /* not ours */ }
    for (const n of readdirSync(d)) fix(join(d, n));
  };
  try { fix(dir); rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

/** Removes this user's private folders of runs that died (older than STALE_MS). */
function sweepStale(now: number): void {
  const uid = process.getuid?.();
  let names: string[];
  try { names = readdirSync(tmpdir()); } catch { return; }
  for (const n of names) {
    if (!n.startsWith(HOOK_TMP_PREFIX)) continue;
    const p = join(tmpdir(), n);
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (st === undefined || st.isSymbolicLink() || !st.isDirectory() || (uid !== undefined && st.uid !== uid) || now - st.mtimeMs < STALE_MS) continue;
    removeTree(p);
  }
}

/** What the user sees for a finding: the index path, the line and the rule; never the value. */
function findingLine(f: { file?: string; displayPath?: string; line?: number; ruleId: string }): string {
  const where = safeText(f.file ?? f.displayPath ?? '(a file with an unusual name)', 200);
  return `  ${where}${f.line === undefined ? '' : `:${f.line}`} (${safeText(f.ruleId.replace(/^secret:/, ''), 80)})`;
}

/** Runs the staged secret scan for the repository holding `dir`. 0: clean; 1: a secret was found; 2: the scan could not run or was not complete. */
export async function hookSecrets(io: CliIO, dir: string, deps: HookSecretsDeps = {}): Promise<number> {
  let tmp: string | null = null;
  const onSignal = (sig: NodeJS.Signals): void => {
    if (tmp !== null) removeTree(tmp);
    process.exit(sig === 'SIGINT' ? 130 : 143);
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  try {
    const env: NodeJS.ProcessEnv = { ...io.env, GIT_NO_REPLACE_OBJECTS: '1' };
    for (const k of Object.keys(env)) if (k.startsWith('GITLEAKS_')) delete env[k];
    const git = deps.git ?? spawnGit;
    sweepStale((deps.now ?? Date.now)());
    const topR = await git(['rev-parse', '--show-toplevel'], { cwd: dir, env });
    const top = topR.stdout.toString('utf8').replace(/\n$/, '');
    if (topR.code !== 0 || top === '' || top.includes('\n')) throw new HookError('this folder is not inside a git repository (git rev-parse --show-toplevel failed).');
    const blobs = await stagedBlobs(git, top, env);
    if (blobs.length === 0) return 0;
    const bin = await (deps.gitleaks ?? (() => ensurePinnedBinary('gitleaks')))();
    tmp = await mkdtemp(join(tmpdir(), HOOK_TMP_PREFIX));
    const exported = join(tmp, 'export');
    await mkdir(exported, { mode: 0o700 });
    await exportBlobs(git, top, env, exported, blobs);
    const stage = join(tmp, 'stage');
    const staged = stageWorkspace({ workspace: exported, stage });
    if (staged.status !== 'ok') throw new HookError(staged.error);
    if (staged.files !== blobs.length) throw new HookError('not every staged file could be prepared for the scan.');
    const config = join(tmp, 'gitleaks.toml');
    await writeFile(config, SECRETS_SCAN_CONFIG, { mode: 0o600, flag: 'wx' });
    const ignoreDir = join(tmp, 'ignore');
    await mkdir(ignoreDir, { mode: 0o700 });
    const report = join(tmp, HOOK_REPORT);
    const code = await (deps.exec ?? spawnExec)(bin, hookSecretsArgv(config, ignoreDir, report), { cwd: join(stage, STAGE_FILES_DIR), env });
    if (code === -1) throw new HookError('the scanner was stopped before it finished (killed by a signal).');
    if (code !== HOOK_SECRETS_EXIT.clean && code !== HOOK_SECRETS_EXIT.found) throw new HookError(`the scanner failed (it exited with ${code}).`);
    let text: Buffer;
    try { text = await readFile(report); } catch { throw new HookError('the scanner wrote no report.'); }
    const parsed = parseSarifText(text, 'gitleaks', { workspace: join(stage, STAGE_FILES_DIR), exactNames: STAGED_NAME_RE });
    if (parsed.toolError !== undefined) throw new HookError(`the scanner's report could not be read (${safeText(parsed.toolError, 200)}).`);
    let mapped: ReturnType<typeof applyStage>;
    try { mapped = applyStage(parsed.findings, readStage(stage), 'gitleaks'); } catch (e) {
      throw new HookError(e instanceof StageError ? `${e.message}.` : "the scanner's findings could not be mapped back to the staged files.");
    }
    const secrets = mapped.findings.filter((f) => f.ruleId !== NOT_SCANNED_RULE);
    const unscanned = mapped.findings.filter((f) => f.ruleId === NOT_SCANNED_RULE);
    if (secrets.length > 0) {
      io.err(["pipegen's secret scan found a secret in your staged changes (the value is not shown):", ...secrets.slice(0, 50).map(findingLine),
        ...(secrets.length > 50 ? [`  and ${secrets.length - 50} more`] : []),
        'Remove it from the files and from the staging area, then commit again. If it was a real secret, rotate it.'].join('\n'));
      return 1;
    }
    if (unscanned.length > 0) {
      io.err(["pipegen's secret scan could not prove it read every staged file, so the commit is blocked:", ...unscanned.slice(0, 50).map(findingLine)].join('\n'));
      return 2;
    }
    return 0;
  } catch (e) {
    const why = e instanceof HookError || e instanceof Error ? e.message : String(e);
    io.err(`pipegen's secret scan could not run: ${safeText(why, 400)} The commit is blocked until it can.`);
    return 2;
  } finally {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    if (tmp !== null) removeTree(tmp);
  }
}
