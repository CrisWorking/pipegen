// v0.2 Plan G, sub-task G6 (the secrets-hook carry): `pipegen hook secrets`, the command pipegen's secrets hook runs. It exports the staged
// text of the changed regular files into a private temp folder and runs pipegen's PINNED gitleaks (ensurePinnedBinary) on it with the reviewed
// config only (never the repo's .gitleaks.toml or .gitleaksignore), redacted output, inline allow comments ignored. Found → the commit is
// blocked; a scan that can't run blocks it too. A real git repo in a temp folder; the scanner is a fake that reads what it was given.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { HOOK_SECRETS_EXIT, hookSecrets, hookSecretsArgv } from '../src/cli/hook.js';
import { run } from '../src/cli/main.js';
import type { CliIO } from '../src/cli/io.js';
import { PinnedBinaryError } from '../src/engine/linters.js';
import { SECRETS_SCAN_CONFIG } from '../src/engine/tool-flags.js';
import { entry } from './helpers/render.js';

const made: string[] = [];
afterEach(() => { for (const x of made.splice(0)) rmSync(x, { recursive: true, force: true }); });
const ENV = { PATH: process.env.PATH, HOME: process.env.HOME, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } as NodeJS.ProcessEnv;
const git = (dir: string, ...args: string[]): string => execFileSync('git', args, { cwd: dir, env: ENV, encoding: 'utf8' });
/** A repo with one commit, then `staged` written and staged, and `unstaged` written only. */
function repo(staged: Record<string, string>, unstaged: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-hook-test-'));
  made.push(dir);
  git(dir, 'init', '-q');
  git(dir, '-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '--allow-empty', '-m', 'i');
  writeFileSync(join(dir, 'kept.txt'), 'old\n');
  git(dir, 'add', 'kept.txt');
  git(dir, '-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '-m', 'k');
  for (const [p, t] of Object.entries(staged)) writeFileSync(join(dir, p), t);
  if (Object.keys(staged).length > 0) git(dir, 'add', ...Object.keys(staged));
  for (const [p, t] of Object.entries(unstaged)) writeFileSync(join(dir, p), t);
  return dir;
}
function io(env: NodeJS.ProcessEnv = ENV): CliIO & { errs: string[] } {
  const errs: string[] = [];
  return { errs, out: () => {}, err: (s) => { errs.push(s); }, env, prompt: { confirm: async () => false, select: async (_m, _o, d) => d, text: async () => '' } };
}
interface Seen { file: string; args: string[]; cwd: string; env: NodeJS.ProcessEnv; config: string; files: Record<string, string>; modes: number[]; ignoreHasFile: boolean }
/** A fake scanner that records what it was given (the exported files and the config) and exits with `code`. */
function scanner(code: number, seen: Seen[]): (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }) => Promise<number> {
  return async (file, args, opts) => {
    const entries = readdirSync(opts.cwd, { recursive: true, withFileTypes: true }).filter((e) => e.isFile());
    const files = Object.fromEntries(entries.map((e) => [join(e.parentPath, e.name).slice(opts.cwd.length + 1), readFileSync(join(e.parentPath, e.name), 'utf8')]));
    const modes = entries.map((e) => statSync(join(e.parentPath, e.name)).mode & 0o777);
    const ign = args[args.indexOf('--gitleaks-ignore-path') + 1] as string;
    seen.push({ file, args, cwd: opts.cwd, env: opts.env, config: readFileSync(args[args.indexOf('--config') + 1] as string, 'utf8'), files, modes, ignoreHasFile: existsSync(join(ign, '.gitleaksignore')) });
    return code;
  };
}

describe('G6: pipegen hook secrets', () => {
  it('the secrets hook command: runs the pinned gitleaks on the staged text with the reviewed config, redacted; found blocks the commit', async () => {
    const dir = repo({ 'new.txt': 'staged secret here\n', 'kept.txt': 'old\nchanged\n', '.gitleaksignore': 'new.txt:some-rule:1\n' }, { 'new.txt': 'the working copy differs\n', 'loose.txt': 'never staged\n' });
    const seen: Seen[] = [];
    const t = io({ ...ENV, GITLEAKS_CONFIG: '/evil.toml', GITLEAKS_CONFIG_TOML: 'x' });
    const code = await hookSecrets(t, dir, { gitleaks: async () => '/cache/gitleaks-8.30.1/gitleaks', exec: scanner(HOOK_SECRETS_EXIT.found, seen) });
    expect(code).toBe(1);
    expect(t.errs.join('\n')).toMatch(/found a secret in your staged changes/);
    const c = seen[0] as Seen;
    expect(c.file).toBe('/cache/gitleaks-8.30.1/gitleaks');
    // exactly the staged text of the changed files: not the working copy, not an unstaged file, not an unchanged one
    // a staged ignore list is scanned under another name, never read as the scanner's own (live: gitleaks reads one at the scan root)
    expect(c.files).toEqual({ 'new.txt': 'staged secret here\n', 'kept.txt': 'old\nchanged\n', '.gitleaksignore.pipegen-scanned': 'new.txt:some-rule:1\n' });
    // the reviewed config (the gitleaks entry's, the one CI uses), never the repo's; the ignore folder holds no .gitleaksignore
    expect(c.config).toBe(SECRETS_SCAN_CONFIG);
    expect(c.config).toBe(entry('gitleaks').fixedInputs?.config?.content);
    expect(c.ignoreHasFile).toBe(false);
    expect(c.args).toEqual(hookSecretsArgv(c.args[c.args.indexOf('--config') + 1] as string, c.args[c.args.indexOf('--gitleaks-ignore-path') + 1] as string));
    expect(c.args[0]).toBe('dir');
    for (const flag of ['--redact', '--ignore-gitleaks-allow', '--no-banner']) expect(c.args).toContain(flag);
    expect(c.args.join(' ')).toContain(`--exit-code ${HOOK_SECRETS_EXIT.found}`);
    expect(c.args).not.toContain('--report-path');
    expect(c.args.at(-1)).toBe('.');
    // gitleaks' own config variables can't pick another config
    expect(c.env.GITLEAKS_CONFIG).toBeUndefined();
    expect(c.env.GITLEAKS_CONFIG_TOML).toBeUndefined();
    // the temp folder is gone afterwards
    expect(existsSync(c.cwd)).toBe(false);
  });

  it('the secrets hook command: nothing staged → 0 without the scanner; links are not exported; clean → 0', async () => {
    let asked = 0;
    const none = io();
    expect(await hookSecrets(none, repo({}, { 'loose.txt': 'x\n' }), { gitleaks: async () => { asked++; return '/g'; }, exec: async () => { asked++; return 0; } })).toBe(0);
    expect(asked).toBe(0);
    const dir = repo({ 'a.txt': 'a\n' });
    symlinkSync('/etc/passwd', join(dir, 'link'));
    git(dir, 'add', 'link');
    const seen: Seen[] = [];
    expect(await hookSecrets(io(), dir, { gitleaks: async () => '/g', exec: scanner(HOOK_SECRETS_EXIT.clean, seen) })).toBe(0);
    expect(Object.keys((seen[0] as Seen).files)).toEqual(['a.txt']);
    // every scanner config or ignore name, at any depth and in any case, is renamed; a clash with a staged file of the new name fails closed
    const names = repo({ '.GitleaksIgnore': 'a\n', '.betterleaksignore': 'b\n', '.gitleaks.toml': 'c\n', '.betterleaks.toml': 'd\n' });
    const seen2: Seen[] = [];
    expect(await hookSecrets(io(), names, { gitleaks: async () => '/g', exec: scanner(HOOK_SECRETS_EXIT.clean, seen2) })).toBe(0);
    expect(Object.keys((seen2[0] as Seen).files).sort()).toEqual(['.GitleaksIgnore.pipegen-scanned', '.betterleaks.toml.pipegen-scanned', '.betterleaksignore.pipegen-scanned', '.gitleaks.toml.pipegen-scanned']);
    const clash = repo({ '.gitleaksignore': 'a\n', '.gitleaksignore.pipegen-scanned': 'b\n' });
    expect(await hookSecrets(io(), clash, { gitleaks: async () => '/g', exec: async () => 0 })).toBe(2);
    // a deleted file is not scanned (there is nothing of it to commit)
    const del = repo({});
    git(del, 'rm', '-q', 'kept.txt');
    expect(await hookSecrets(io(), del, { gitleaks: async () => { throw new Error('not asked'); }, exec: async () => 0 })).toBe(0);
  });

  it('the secrets hook command: a type change (a link replaced by a file holding a key) is scanned (G6-R-sec1, 1)', async () => {
    const dir = repo({});
    symlinkSync('kept.txt', join(dir, 'link'));
    git(dir, 'add', 'link');
    git(dir, '-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '-m', 'l');
    rmSync(join(dir, 'link'));
    writeFileSync(join(dir, 'link'), 'fake key here\n');
    git(dir, 'add', 'link');
    expect(git(dir, 'diff', '--cached', '--name-status')).toMatch(/^T\tlink/m);
    const seen: Seen[] = [];
    const found = async (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): Promise<number> => {
      await scanner(0, seen)(file, args, opts);
      return [HOOK_SECRETS_EXIT.clean, HOOK_SECRETS_EXIT.found][Number(Object.values((seen.at(-1) as Seen).files).some((t) => t.includes('fake key')))] as number;
    };
    expect(await hookSecrets(io(), dir, { gitleaks: async () => '/g', exec: found })).toBe(1);
    expect((seen[0] as Seen).files).toEqual({ link: 'fake key here\n' });
  });

  it('the secrets hook command: the raw staged blobs are scanned, never a .gitattributes-filtered copy (G6-R-sec1, 2)', async () => {
    const seen: Seen[] = [];
    const found = async (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): Promise<number> => {
      await scanner(0, seen)(file, args, opts);
      return [HOOK_SECRETS_EXIT.clean, HOOK_SECRETS_EXIT.found][Number(Object.values((seen.at(-1) as Seen).files).some((t) => t.includes('fake key')))] as number;
    };
    // a smudge filter that would rewrite the text on checkout, and an eol / ident attribute: the scanner sees the blob's bytes
    const dir = repo({ '.gitattributes': '*.txt filter=hide ident eol=crlf\n*.enc working-tree-encoding=UTF-16LE\n' });
    git(dir, 'config', 'filter.hide.smudge', 'echo nothing to see');
    git(dir, 'config', 'filter.hide.clean', 'cat');
    writeFileSync(join(dir, 'a.txt'), 'fake key in a\n');
    git(dir, 'add', 'a.txt');
    expect(await hookSecrets(io(), dir, { gitleaks: async () => '/g', exec: found })).toBe(1);
    const files = (seen[0] as Seen).files;
    expect(files['a.txt']).toBe('fake key in a\n');
    expect(files['.gitattributes']).toContain('filter=hide');
    // working-tree-encoding: the blob is UTF-8, the checkout would be UTF-16 (the scanner would read no plain text)
    const enc = repo({ '.gitattributes': '*.enc working-tree-encoding=UTF-16LE\n' });
    writeFileSync(join(enc, 'b.enc'), Buffer.from('fake key in b\n', 'utf16le'));
    git(enc, 'add', 'b.enc');
    const seen2: Seen[] = [];
    const found2 = async (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): Promise<number> => {
      await scanner(0, seen2)(file, args, opts);
      return [HOOK_SECRETS_EXIT.clean, HOOK_SECRETS_EXIT.found][Number(Object.values((seen2.at(-1) as Seen).files).some((t) => t.includes('fake key')))] as number;
    };
    expect(await hookSecrets(io(), enc, { gitleaks: async () => '/g', exec: found2 })).toBe(1);
    expect((seen2[0] as Seen).files['b.enc']).toBe('fake key in b\n');
    // the exported files are private (0600) and stay inside the folder
    expect((seen2[0] as Seen).modes.every((m) => m === 0o600)).toBe(true);
  });

  it('the secrets hook command: a scanner error, a pinned binary that does not check out, or no git repo blocks the commit (fail closed)', async () => {
    const dir = repo({ 'a.txt': 'a\n' });
    for (const code of [1, 2, 126, -1]) {
      const t = io();
      expect(await hookSecrets(t, dir, { gitleaks: async () => '/g', exec: async () => code }), String(code)).toBe(2);
      expect(t.errs.join('\n')).toMatch(/could not run/);
    }
    const bad = io();
    expect(await hookSecrets(bad, dir, { gitleaks: async () => { throw new PinnedBinaryError('The download of gitleaks 8.30.1 doesn\'t match its pinned checksum'); }, exec: async () => 0 })).toBe(2);
    expect(bad.errs.join('\n')).toMatch(/pinned checksum/);
    expect(await hookSecrets(io(), dir, { gitleaks: async () => '/g', exec: async () => { throw new Error('spawn ENOENT'); } })).toBe(2);
    const notRepo = mkdtempSync(join(tmpdir(), 'pipegen-hook-norepo-'));
    made.push(notRepo);
    const t = io({ ...ENV, GIT_CEILING_DIRECTORIES: tmpdir() });
    expect(await hookSecrets(t, notRepo, { gitleaks: async () => '/g', exec: async () => 0 })).toBe(2);
    expect(t.errs.join('\n')).toMatch(/could not list the staged changes/);
  });

  it('the secrets hook command: the CLI takes exactly `pipegen hook secrets`', async () => {
    for (const argv of [['hook'], ['hook', 'other'], ['hook', 'secrets', 'x'], ['hook', 'secrets', '--json']]) {
      expect(await run(argv, io()), argv.join(' ')).toBe(1);
    }
  });
});
