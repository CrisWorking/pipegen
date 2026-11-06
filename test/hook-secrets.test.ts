// v0.2 Plan G, sub-task G6 (the secrets-hook carry; rulings G6-R-sec1, G6-R2): `pipegen hook secrets`, the command pipegen's secrets hook runs.
// It exports the RAW staged blobs, stages them as the gate stages a checkout in CI (neutral names, a prefix line, a canary per file) and runs
// pipegen's PINNED gitleaks on the stage folder with the reviewed config only. Any finding blocks the commit; so does a file whose canary was
// not reported exactly once, and a scan that can't run. A real git repo in a temp folder; the scanner is a fake that writes the SARIF a full
// scan writes (each canary, and every `fake key` text), except in the live tests at the end, which run the real pinned binary when cached.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HOOK_REPORT, HOOK_SECRETS_EXIT, HOOK_TMP_PREFIX, hookSecrets, hookSecretsArgv } from '../src/cli/hook.js';
import { run } from '../src/cli/main.js';
import type { CliIO } from '../src/cli/io.js';
import { ensurePinnedBinary, PinnedBinaryError } from '../src/engine/linters.js';
import { SECRETS_SCAN_CONFIG } from '../src/engine/tool-flags.js';
import { entry } from './helpers/render.js';

const made: string[] = [];
afterEach(() => { for (const x of made.splice(0)) rmSync(x, { recursive: true, force: true }); });
const ENV = { PATH: process.env.PATH, HOME: process.env.HOME, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } as NodeJS.ProcessEnv;
const git = (dir: string, ...args: string[]): string => execFileSync('git', args, { cwd: dir, env: ENV, encoding: 'utf8' });
const commit = (dir: string, m: string): void => { git(dir, '-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '--allow-empty', '-m', m); };
/** A repo with one commit holding kept.txt, then `staged` written and staged, and `unstaged` written only. */
function repo(staged: Record<string, string | Buffer>, unstaged: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-hook-test-'));
  made.push(dir);
  git(dir, 'init', '-q');
  writeFileSync(join(dir, 'kept.txt'), 'old\n');
  git(dir, 'add', 'kept.txt');
  commit(dir, 'k');
  for (const [p, t] of Object.entries(staged)) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), t); }
  if (Object.keys(staged).length > 0) git(dir, 'add', '-f', ...Object.keys(staged));
  for (const [p, t] of Object.entries(unstaged)) writeFileSync(join(dir, p), t);
  return dir;
}
function io(env: NodeJS.ProcessEnv = ENV): CliIO & { errs: string[] } {
  const errs: string[] = [];
  return { errs, out: () => {}, err: (s) => { errs.push(s); }, env, prompt: { confirm: async () => false, select: async (_m, _o, d) => d, text: async () => '' } };
}

// ---------- the fake scanner: the SARIF a full gitleaks scan of the stage folder writes ----------

interface Entry { name: string; path: string; offset: number; length: number; canary: string }
interface Seen { file: string; args: string[]; cwd: string; env: NodeJS.ProcessEnv; config: string; files: Record<string, string>; names: string[]; modes: number[]; ignoreEmpty: boolean }
interface Hit { rule: string; uri: string; startLine: number; startColumn: number; endLine: number; endColumn: number }
/** Where `needle` is in a staged file, as gitleaks reports it: bytes from 1, end inclusive, one more on every line after the first. */
function hitFor(files: string, name: string, needle: string, rule: string): Hit | null {
  const bytes = readFileSync(join(files, name));
  const at = bytes.indexOf(needle);
  if (at < 0) return null;
  const before = bytes.subarray(0, at);
  const line = before.filter((c) => c === 0x0a).length + 1;
  const col = at - (before.lastIndexOf(0x0a) + 1) + 1 + (line >= 2 ? 1 : 0);
  return { rule, uri: name, startLine: line, startColumn: col, endLine: line, endColumn: col + Buffer.byteLength(needle) - 1 };
}
const sarif = (hits: readonly Hit[]): string => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks', rules: [] } }, results: hits.map((h) => ({
  message: { text: `${h.rule} has detected secret for file ${h.uri}.` }, ruleId: h.rule,
  locations: [{ physicalLocation: { artifactLocation: { uri: h.uri }, region: { startLine: h.startLine, startColumn: h.startColumn, endLine: h.endLine, endColumn: h.endColumn, snippet: { text: 'REDACTED' } } } }],
  partialFingerprints: { commitSha: '', email: '', author: '', date: '', commitMessage: '' }, properties: { tags: [] },
})) }] });
/** A fake scanner: records what it was given, reports every canary (but `drop`) and every `fake key`, exits like gitleaks. */
function scanner(seen: Seen[], o: { drop?: boolean; exit?: number } = {}): (file: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }) => Promise<number> {
  return async (file, args, opts) => {
    const manifest = JSON.parse(readFileSync(join(opts.cwd, '..', 'manifest.json'), 'utf8')) as { files: Entry[] };
    const names = readdirSync(opts.cwd);
    const files: Record<string, string> = {};
    const hits: Hit[] = [];
    for (const e of manifest.files) {
      const b = readFileSync(join(opts.cwd, e.name));
      files[Buffer.from(e.path, 'base64').toString('utf8')] = b.subarray(1, 1 + e.length).toString('utf8');
      const c = hitFor(opts.cwd, e.name, e.canary, 'pipegen-canary');
      if (c !== null && o.drop !== true) hits.push(c);
      const k = hitFor(opts.cwd, e.name, 'fake key', 'generic-api-key');
      if (k !== null) hits.push(k);
    }
    const at = (flag: string): string => args[args.indexOf(flag) + 1] as string;
    writeFileSync(at('--report-path'), sarif(hits));
    seen.push({ file, args, cwd: opts.cwd, env: opts.env, config: readFileSync(at('--config'), 'utf8'), files, names, modes: names.map((n) => statSync(join(opts.cwd, n)).mode & 0o777), ignoreEmpty: readdirSync(at('--gitleaks-ignore-path')).length === 0 });
    return o.exit ?? [HOOK_SECRETS_EXIT.clean, HOOK_SECRETS_EXIT.found][Number(hits.length > 0)] as number;
  };
}
const G = async (): Promise<string> => '/cache/gitleaks-8.30.1/gitleaks';

describe('G6: pipegen hook secrets', () => {
  it('the secrets hook command: runs the pinned gitleaks on the staged text, staged under neutral names with the reviewed config; found blocks the commit', async () => {
    const dir = repo({ 'new.txt': 'staged fake key here\n', 'kept.txt': 'old\nchanged\n', '.gitleaksignore': 'new.txt:some-rule:1\n' }, { 'new.txt': 'the working copy differs\n', 'loose.txt': 'never staged\n' });
    const seen: Seen[] = [];
    const t = io({ ...ENV, GITLEAKS_CONFIG: '/evil.toml', GITLEAKS_CONFIG_TOML: 'x' });
    expect(await hookSecrets(t, dir, { gitleaks: G, exec: scanner(seen) })).toBe(1);
    // the message names the index path and line, never the value
    expect(t.errs.join('\n')).toMatch(/found a secret in your staged changes/);
    expect(t.errs.join('\n')).toMatch(/new\.txt:1 \(generic-api-key\)/);
    const c = seen[0] as Seen;
    expect(c.file).toBe('/cache/gitleaks-8.30.1/gitleaks');
    // exactly the staged text of the changed files (not the working copy, not an unstaged or unchanged file), under neutral names only
    expect(c.files).toEqual({ 'new.txt': 'staged fake key here\n', 'kept.txt': 'old\nchanged\n', '.gitleaksignore': 'new.txt:some-rule:1\n' });
    expect(c.names.every((n) => /^f\d{8}\./.test(n))).toBe(true);
    // the reviewed config (the gitleaks entry's, the one CI uses, with the canary rule), never the repo's; an empty ignore folder
    expect(c.config).toBe(SECRETS_SCAN_CONFIG);
    expect(c.config).toBe(entry('gitleaks').fixedInputs?.config?.content);
    expect(c.config).toContain('pipegen-canary');
    expect(c.ignoreEmpty).toBe(true);
    const at = (flag: string): string => c.args[c.args.indexOf(flag) + 1] as string;
    expect(c.args).toEqual(hookSecretsArgv(at('--config'), at('--gitleaks-ignore-path'), at('--report-path')));
    expect(at('--report-path').endsWith(HOOK_REPORT)).toBe(true);
    for (const flag of ['--redact', '--ignore-gitleaks-allow', '--no-banner']) expect(c.args).toContain(flag);
    expect(c.args).not.toContain('--verbose');
    expect(c.env.GITLEAKS_CONFIG).toBeUndefined();
    expect(c.env.GITLEAKS_CONFIG_TOML).toBeUndefined();
    expect(c.env.GIT_NO_REPLACE_OBJECTS).toBe('1');
    // the private folder is gone afterwards
    expect(existsSync(c.cwd)).toBe(false);
  });

  it('the secrets hook command: a file whose canary is not reported exactly once blocks the commit (C1)', async () => {
    const dir = repo({ 'a.txt': 'a\n' });
    const t = io();
    expect(await hookSecrets(t, dir, { gitleaks: G, exec: scanner([], { drop: true }) })).toBe(2);
    expect(t.errs.join('\n')).toMatch(/could not prove it read every staged file[\s\S]*a\.txt/);
    // clean when every canary came back
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: scanner([]) })).toBe(0);
  });

  it('the secrets hook command: nothing staged → 0 without the scanner; a link\'s target text is scanned as a plain file; a deletion is not scanned', async () => {
    let asked = 0;
    expect(await hookSecrets(io(), repo({}, { 'loose.txt': 'x\n' }), { gitleaks: async () => { asked++; return '/g'; }, exec: async () => { asked++; return 0; } })).toBe(0);
    expect(asked).toBe(0);
    const dir = repo({ 'a.txt': 'a\n' });
    symlinkSync('fake key in a link', join(dir, 'link'));
    git(dir, 'add', 'link');
    const seen: Seen[] = [];
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: scanner(seen) })).toBe(1);
    expect((seen[0] as Seen).files).toEqual({ 'a.txt': 'a\n', link: 'fake key in a link' });
    const del = repo({});
    git(del, 'rm', '-q', 'kept.txt');
    expect(await hookSecrets(io(), del, { gitleaks: async () => { throw new Error('not asked'); }, exec: async () => 0 })).toBe(0);
  });

  it('the secrets hook command: run from a sub-folder, it scans the whole index (spec I1)', async () => {
    const dir = repo({ 'top.txt': 'fake key at the top\n', 'sub/x.txt': 'fake key below\n' });
    const seen: Seen[] = [];
    const t = io();
    expect(await hookSecrets(t, join(dir, 'sub'), { gitleaks: G, exec: scanner(seen) })).toBe(1);
    expect(Object.keys((seen[0] as Seen).files).sort()).toEqual(['sub/x.txt', 'top.txt']);
    expect(t.errs.join('\n')).toMatch(/sub\/x\.txt:1[\s\S]*top\.txt:1|top\.txt:1[\s\S]*sub\/x\.txt:1/);
  });

  it('the secrets hook command: a type change (a link replaced by a file holding a key) is scanned (G6-R-sec1, 1)', async () => {
    const dir = repo({});
    symlinkSync('kept.txt', join(dir, 'link'));
    git(dir, 'add', 'link');
    commit(dir, 'l');
    rmSync(join(dir, 'link'));
    writeFileSync(join(dir, 'link'), 'fake key here\n');
    git(dir, 'add', 'link');
    expect(git(dir, 'diff', '--cached', '--name-status')).toMatch(/^T\tlink/m);
    const seen: Seen[] = [];
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: scanner(seen) })).toBe(1);
    expect((seen[0] as Seen).files).toEqual({ link: 'fake key here\n' });
  });

  it('the secrets hook command: the raw staged blobs are scanned, never a .gitattributes-filtered copy (G6-R-sec1, 2)', async () => {
    const dir = repo({ '.gitattributes': '*.txt filter=hide ident eol=crlf\n' });
    git(dir, 'config', 'filter.hide.smudge', 'echo nothing to see');
    git(dir, 'config', 'filter.hide.clean', 'cat');
    writeFileSync(join(dir, 'a.txt'), 'fake key in a\n');
    git(dir, 'add', 'a.txt');
    const seen: Seen[] = [];
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: scanner(seen) })).toBe(1);
    expect((seen[0] as Seen).files['a.txt']).toBe('fake key in a\n');
    // working-tree-encoding: the blob is UTF-8, the checkout would be UTF-16 (the scanner would read no plain text)
    const enc = repo({ '.gitattributes': '*.enc working-tree-encoding=UTF-16LE\n' });
    writeFileSync(join(enc, 'b.enc'), Buffer.from('fake key in b\n', 'utf16le'));
    git(enc, 'add', 'b.enc');
    const seen2: Seen[] = [];
    expect(await hookSecrets(io(), enc, { gitleaks: G, exec: scanner(seen2) })).toBe(1);
    expect((seen2[0] as Seen).files['b.enc']).toBe('fake key in b\n');
  });

  it('the secrets hook command: a refs/replace object can not stand in for the staged blob (M5)', async () => {
    const dir = repo({ 'a.txt': 'fake key in a\n' });
    const staged = git(dir, 'rev-parse', ':a.txt').trim();
    const clean = execFileSync('git', ['hash-object', '-w', '--stdin'], { cwd: dir, env: ENV, input: 'nothing here\n', encoding: 'utf8' }).trim();
    git(dir, 'replace', staged, clean);
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: scanner([]) })).toBe(1);
  });

  it('the secrets hook command: an index path that would leave the private folder fails closed (G6-R-sec1)', async () => {
    const oid = 'a'.repeat(40);
    for (const path of ['../escape.txt', '/abs.txt', 'a//b', 'a/./b', 'a\\b']) {
      let wrote = false;
      const fake = async (args: string[]): Promise<{ code: number; stdout: Buffer }> => {
        if (args[0] === 'rev-parse') return { code: 0, stdout: Buffer.from('/repo\n') };
        if (args[0] === 'diff') return { code: 0, stdout: Buffer.from(`:000000 100644 ${'0'.repeat(40)} ${oid} A\0${path}\0`) };
        wrote = true;
        return { code: 0, stdout: Buffer.from(`${oid} blob 1\nx\n`) };
      };
      expect(await hookSecrets(io(), '/repo', { git: fake, gitleaks: G, exec: async () => 0 }), path).toBe(2);
      expect(wrote, path).toBe(false);
    }
    // an unknown mode or an unreadable record fails closed too
    for (const out of [`:000000 100600 ${'0'.repeat(40)} ${oid} A\0x\0`, `:000000 100644 ${oid} A\0x\0`, 'garbage\0x\0']) {
      const fake = async (args: string[]): Promise<{ code: number; stdout: Buffer }> => (args[0] === 'rev-parse' ? { code: 0, stdout: Buffer.from('/repo\n') } : { code: 0, stdout: Buffer.from(out) });
      expect(await hookSecrets(io(), '/repo', { git: fake, gitleaks: G, exec: async () => 0 }), out).toBe(2);
    }
  });

  it('the secrets hook command: plain messages for a stopped scanner, a case clash and the size cap (spec m2, m3)', async () => {
    const dir = repo({ 'a.txt': 'a\n' });
    const stopped = io();
    expect(await hookSecrets(stopped, dir, { gitleaks: G, exec: async () => -1 })).toBe(2);
    expect(stopped.errs.join('\n')).toMatch(/stopped before it finished/);
    const oid = 'a'.repeat(40);
    const clash = async (args: string[]): Promise<{ code: number; stdout: Buffer }> => {
      if (args[0] === 'rev-parse') return { code: 0, stdout: Buffer.from('/repo\n') };
      if (args[0] === 'diff') return { code: 0, stdout: Buffer.from(`:000000 100644 ${'0'.repeat(40)} ${oid} A\0a\0:000000 100644 ${'0'.repeat(40)} ${oid} A\0a/b\0`) };
      return { code: 0, stdout: Buffer.from(`${oid} blob 1\nx\n${oid} blob 1\nx\n`) };
    };
    const c = io();
    expect(await hookSecrets(c, '/repo', { git: clash, gitleaks: G, exec: async () => 0 })).toBe(2);
    expect(c.errs.join('\n')).toMatch(/same name on this disk/);
    const big = async (args: string[]): Promise<{ code: number; stdout: Buffer }> => {
      if (args[0] === 'rev-parse') return { code: 0, stdout: Buffer.from('/repo\n') };
      if (args[0] === 'diff') return { code: 0, stdout: Buffer.from(`:000000 100644 ${'0'.repeat(40)} ${oid} A\0a\0`) };
      return { code: -2, stdout: Buffer.alloc(0) };
    };
    const b = io();
    expect(await hookSecrets(b, '/repo', { git: big, gitleaks: G, exec: async () => 0 })).toBe(2);
    expect(b.errs.join('\n')).toMatch(/larger than \d+ MiB in all/);
  });

  it('the secrets hook command: stale private folders of this user are swept; fresh ones are kept (M7)', async () => {
    const old = mkdtempSync(join(tmpdir(), HOOK_TMP_PREFIX));
    const fresh = mkdtempSync(join(tmpdir(), HOOK_TMP_PREFIX));
    made.push(old, fresh);
    writeFileSync(join(old, 'left.txt'), 'x');
    const hour = (Date.now() - 3_600_000) / 1000;
    utimesSync(old, hour, hour);
    expect(await hookSecrets(io(), repo({}), {})).toBe(0);
    expect(existsSync(old)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });

  it('the secrets hook command: a hangup, quit, interrupt or stop mid-scan removes the private folder (M7, N4)', async () => {
    for (const [sig, code] of [['SIGHUP', 129], ['SIGQUIT', 131], ['SIGINT', 130], ['SIGTERM', 143]] as const) {
      const before = process.listeners(sig).length;
      const exits: (number | undefined)[] = [];
      const exit = vi.spyOn(process, 'exit').mockImplementation(((c?: number) => { exits.push(c); }) as never);
      let tmp = '';
      try {
        const res = await hookSecrets(io(), repo({ 'a.txt': 'x\n' }), {
          gitleaks: G,
          exec: async (_f, _a, opts) => {
            tmp = dirname(dirname(opts.cwd));
            expect(existsSync(tmp), sig).toBe(true);
            const added = process.listeners(sig).slice(before);
            expect(added.length, sig).toBe(1);
            (added[0] as (s: NodeJS.Signals) => void)(sig);
            return 0;
          },
        });
        expect(res, sig).toBe(2);
      } finally {
        exit.mockRestore();
      }
      expect(exits, sig).toEqual([code]);
      expect(tmp.startsWith(join(tmpdir(), HOOK_TMP_PREFIX)), tmp).toBe(true);
      expect(existsSync(tmp), sig).toBe(false);
      expect(process.listeners(sig).length, sig).toBe(before);
    }
  });

  it('the secrets hook command: a scanner error, a pinned binary that does not check out, or no git repo blocks the commit (fail closed)', async () => {
    const dir = repo({ 'a.txt': 'a\n' });
    for (const code of [1, 2, 126]) {
      const t = io();
      expect(await hookSecrets(t, dir, { gitleaks: G, exec: async () => code }), String(code)).toBe(2);
      expect(t.errs.join('\n')).toMatch(/could not run/);
    }
    // a clean exit with no report, or a report that is not SARIF
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: async () => 0 })).toBe(2);
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: async (_f, args) => { writeFileSync(args[args.indexOf('--report-path') + 1] as string, '{'); return 0; } })).toBe(2);
    const bad = io();
    expect(await hookSecrets(bad, dir, { gitleaks: async () => { throw new PinnedBinaryError('The download of gitleaks 8.30.1 doesn\'t match its pinned checksum'); }, exec: async () => 0 })).toBe(2);
    expect(bad.errs.join('\n')).toMatch(/pinned checksum/);
    expect(await hookSecrets(io(), dir, { gitleaks: G, exec: async () => { throw new Error('spawn ENOENT'); } })).toBe(2);
    const notRepo = mkdtempSync(join(tmpdir(), 'pipegen-hook-norepo-'));
    made.push(notRepo);
    const t = io({ ...ENV, GIT_CEILING_DIRECTORIES: tmpdir() });
    expect(await hookSecrets(t, notRepo, { gitleaks: G, exec: async () => 0 })).toBe(2);
    expect(t.errs.join('\n')).toMatch(/not inside a git repository/);
  });

  it('the secrets hook command: the CLI takes exactly `pipegen hook secrets`', async () => {
    for (const argv of [['hook'], ['hook', 'other'], ['hook', 'secrets', 'x'], ['hook', 'secrets', '--json']]) {
      expect(await run(argv, io()), argv.join(' ')).toBe(1);
    }
  });
});

// ---------- live: the real pinned gitleaks (skipped when it is not in the tool cache) ----------

const CACHED = existsSync(join(process.env.XDG_CACHE_HOME ?? join(homedir(), '.cache'), 'pipegen', 'tools', 'gitleaks-8.30.1', 'gitleaks'));
/** A live-looking key, built at run time (test/no-secret-literals.test.ts). */
/** The assignment the keys sit in (spelled at run time, test/no-secret-literals.test.ts). */
const SET = `${['to', 'ken'].join('')} = "`;
const key = (seed: string): string => `${'sk'}${'_live_'}${createHash('sha256').update(seed).digest('hex').slice(0, 24)}`;
const pinned = (): Promise<string> => ensurePinnedBinary('gitleaks', undefined, { fetch: (async () => { throw new Error('no network in tests'); }) as typeof fetch });

describe.skipIf(!CACHED)('G6 live: the real pinned gitleaks 8.30.1 (C1)', () => {
  it('the secrets hook command (live): a key in an allowlisted path or an archive-looking file is still found', async () => {
    const cases: Record<string, string | Buffer> = {
      '.gitleaks.toml': `${SET}${key('a')}"\n`, 'sub/.gitleaks.toml': `${SET}${key('b')}"\n`, 'package-lock.json': `{"k": "${key('c')}"}\n`,
      'docs/a.svg': `<svg>\n${SET}${key('d')}"\n</svg>\n`, 'node_modules/x.js': `const k = "${key('e')}";\n`,
      blob: Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from(`\nconst k = "${key('f')}";\n`)]),
    };
    for (const [path, text] of Object.entries(cases)) {
      const t = io();
      expect(await hookSecrets(t, repo({ [path]: text }), { gitleaks: pinned }), path).toBe(1);
      expect(t.errs.join('\n'), path).toContain(`${path}:`);
    }
  });

  it('the secrets hook command (live): a clean commit passes; a one-line staged key is blocked', async () => {
    expect(await hookSecrets(io(), repo({ 'a.txt': 'nothing here\n' }), { gitleaks: pinned })).toBe(0);
    expect(await hookSecrets(io(), repo({ 'one.txt': `${key('g')}\n` }), { gitleaks: pinned })).toBe(1);
  });
});
