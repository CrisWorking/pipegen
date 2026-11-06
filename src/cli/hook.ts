// `pipegen hook secrets` (v0.2 Plan G, G6: the secrets-hook carry). The command pipegen's local secrets hook runs at every commit
// (src/engine/created-builders.ts secretsHookRun: `npx --yes --registry=https://registry.npmjs.org pipegen@<exact> hook secrets`).
//
// It runs pipegen's PINNED gitleaks (data/pinned-binaries.yml; ensurePinnedBinary downloads it once and re-hashes it before every use) on what
// is about to be committed: the staged text of every added, copied, modified or renamed regular file, exported from the git index into a
// private temp folder (`git checkout-index`), scanned with `gitleaks dir`, the mode CI runs. Not `gitleaks git --staged` (nor the old
// `protect --staged`): live, gitleaks 8.30.1 misses a secret on the first added line of a staged hunk, so a one-line file passes.
// The scan uses the reviewed config only (the gitleaks entry's, the one CI uses; never the repository's .gitleaks.toml, nor GITLEAKS_CONFIG),
// an ignore folder with no .gitleaksignore (a repository's ignore list can't hide a finding), inline allow comments ignored, the secret redacted
// in what is printed, and its own exit code for a finding (gitleaks' errors exit 1). A finding blocks the commit; so does a scan that can't run
// (fail closed). Symbolic links and submodules in the index are not exported (only modes 100644 and 100755). A staged scanner config or ignore
// file is scanned under another name, never read as the scanner's own (neutralize). No shell anywhere.
import { spawn } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensurePinnedBinary } from '../engine/linters.js';
import { SECRETS_SCAN_CONFIG } from '../engine/tool-flags.js';
import { safeText } from '../util/safe-text.js';
import type { CliIO } from './io.js';

/** The scanner's exit codes with `--exit-code 10`: nothing found, and found. Any other is an error. */
export const HOOK_SECRETS_EXIT = Object.freeze({ clean: 0, found: 10 });

/** The fixed scanner argv: only the config file and the (empty) ignore folder change; it scans its working folder, the export. */
export function hookSecretsArgv(config: string, ignoreDir: string): string[] {
  return [
    'dir', '--no-banner', '--redact', '--verbose', '--no-color', '--ignore-gitleaks-allow',
    '--config', config, '--gitleaks-ignore-path', ignoreDir, '--exit-code', String(HOOK_SECRETS_EXIT.found), '--max-archive-depth', '0', '--log-level', 'warn', '.',
  ];
}

export interface HookSecretsDeps {
  /** The pinned gitleaks' absolute path, checked just now. Default: ensurePinnedBinary('gitleaks'). */
  gitleaks?: () => Promise<string>;
  /** Runs the scanner without a shell, its output on the terminal; resolves to its exit code (-1: killed). Default: child_process.spawn. */
  exec?: (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }) => Promise<number>;
  /** Runs git without a shell in `cwd` (stdin from `input`); resolves to its exit code and stdout. Default: child_process.spawn of `git`. */
  git?: (args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; input?: Buffer }) => Promise<{ code: number; stdout: Buffer }>;
}

const spawnExec = (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): Promise<number> => new Promise((resolve, reject) => {
  const child = spawn(file, args, { cwd: opts.cwd, env: opts.env, stdio: ['ignore', 'inherit', 'inherit'], shell: false });
  child.on('error', reject);
  child.on('close', (code) => { resolve(code ?? -1); });
});
const MAX_GIT_OUTPUT = 64 * 1024 * 1024;
const spawnGit = (args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; input?: Buffer }): Promise<{ code: number; stdout: Buffer }> => new Promise((resolve, reject) => {
  const child = spawn('git', args, { cwd: opts.cwd, env: opts.env, stdio: [opts.input === undefined ? 'ignore' : 'pipe', 'pipe', 'ignore'], shell: false });
  const chunks: Buffer[] = [];
  let size = 0;
  child.on('error', reject);
  child.stdout?.on('data', (c: Buffer) => { size += c.length; if (size > MAX_GIT_OUTPUT) child.kill(); else chunks.push(c); });
  child.on('close', (code) => { resolve({ code: size > MAX_GIT_OUTPUT ? -1 : code ?? -1, stdout: Buffer.concat(chunks) }); });
  // a git that exits before reading its input gives EPIPE here; its exit code tells what happened
  child.stdin?.on('error', () => {});
  if (opts.input !== undefined) child.stdin?.end(opts.input);
});

/**
 * The scanners' own config and ignore names (CI's stage folder refuses them, gate/src/stage.ts): gitleaks reads a `.gitleaksignore` at the root
 * of the folder it scans, whatever --gitleaks-ignore-path says (live, 8.30.1), so a staged one would hide findings. Each exported file of such a
 * name, at any depth, is renamed with this suffix before the scan: its text is still scanned, it is never read as a list.
 */
const RESERVED_NAMES: ReadonlySet<string> = new Set(['.gitleaksignore', '.betterleaksignore', '.gitleaks.toml', '.betterleaks.toml']);
const RENAMED_SUFFIX = '.pipegen-scanned';
async function neutralize(dir: string): Promise<void> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) { await neutralize(full); continue; }
    if (!e.isFile()) throw new Error('the export of the staged files holds something that is not a plain file.');
    if (!RESERVED_NAMES.has(e.name.toLowerCase())) continue;
    const to = `${full}${RENAMED_SUFFIX}`;
    if (await lstat(to).then(() => true, () => false)) throw new Error(`two staged files would share the scan name ${e.name}${RENAMED_SUFFIX}.`);
    await rename(full, to);
  }
}

/** The staged regular files that change in this commit (added, copied, modified, renamed), as NUL-separated index paths. */
async function stagedFiles(git: NonNullable<HookSecretsDeps['git']>, cwd: string, env: NodeJS.ProcessEnv): Promise<string[]> {
  const changed = await git(['diff', '--cached', '--name-only', '-z', '--no-renames', '--diff-filter=ACMR'], { cwd, env });
  if (changed.code !== 0) throw new Error('git could not list the staged changes.');
  const wanted = new Set(changed.stdout.toString('utf8').split('\0').filter((p) => p !== ''));
  if (wanted.size === 0) return [];
  const index = await git(['ls-files', '--stage', '-z'], { cwd, env });
  if (index.code !== 0) throw new Error('git could not read the index.');
  const out: string[] = [];
  for (const rec of index.stdout.toString('utf8').split('\0')) {
    const m = /^(\d{6}) [0-9a-f]{40,64} 0\t(.+)$/s.exec(rec);
    if (m !== null && (m[1] === '100644' || m[1] === '100755') && wanted.has(m[2] as string)) out.push(m[2] as string);
  }
  return out;
}

/** Runs the staged secret scan in `dir` (the repository root the hook starts in). 0: clean; 1: a secret was found; 2: the scan could not run. */
export async function hookSecrets(io: CliIO, dir: string, deps: HookSecretsDeps = {}): Promise<number> {
  let tmp: string | null = null;
  try {
    const env: NodeJS.ProcessEnv = { ...io.env };
    for (const k of Object.keys(env)) if (k.startsWith('GITLEAKS_')) delete env[k];
    const git = deps.git ?? spawnGit;
    const files = await stagedFiles(git, dir, env);
    if (files.length === 0) return 0;
    const bin = await (deps.gitleaks ?? (() => ensurePinnedBinary('gitleaks')))();
    tmp = await mkdtemp(join(tmpdir(), 'pipegen-hook-'));
    const config = join(tmp, 'gitleaks.toml');
    await writeFile(config, SECRETS_SCAN_CONFIG, { mode: 0o600, flag: 'wx' });
    const stage = join(tmp, 'staged');
    await mkdir(stage, { mode: 0o700 });
    // the index's text of those files, written under the private folder (checkout-index writes no link, it is given regular files only)
    const out = await git(['checkout-index', '-z', '--stdin', `--prefix=${stage}/`], { cwd: dir, env, input: Buffer.from(`${files.join('\0')}\0`, 'utf8') });
    if (out.code !== 0) throw new Error('git could not export the staged files.');
    await neutralize(stage);
    // the temp folder is the ignore folder: it holds no .gitleaksignore
    const code = await (deps.exec ?? spawnExec)(bin, hookSecretsArgv(config, tmp), { cwd: stage, env });
    if (code === HOOK_SECRETS_EXIT.clean) return 0;
    if (code === HOOK_SECRETS_EXIT.found) {
      io.err("pipegen's secret scan found a secret in your staged changes (shown above, redacted). Remove it from the files and from the staging area, then commit again. If it was a real secret, rotate it.");
      return 1;
    }
    io.err(`pipegen's secret scan could not run (the scanner exited with ${code}), so the commit is blocked until it can.`);
    return 2;
  } catch (e) {
    io.err(`pipegen's secret scan could not run: ${safeText(e instanceof Error ? e.message : String(e), 300)} The commit is blocked until it can.`);
    return 2;
  } finally {
    if (tmp !== null) await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}
