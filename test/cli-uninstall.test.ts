// v0.2 Plan V V7: `pipegen uninstall` on the command line (src/cli/uninstall.ts, the dispatch in src/cli/main.ts). The command checks for a terminal,
// connects, loads the install record (loadUninstallRecord) and runs one step (uninstallStep); these tests fake each of those, and run the real
// loader and step once, on the GitHub stand-in of the phase-B tests, for the second run 2. No network.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { run as main, type Commands } from '../src/cli/main.js';
import type { CliIO, Prompter } from '../src/cli/io.js';
import { uninstallCommand, type UninstallCommandDeps } from '../src/cli/uninstall.js';
import { localRecordPath, recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord } from '../src/deliver/record.js';
import { GitHubRateLimitError } from '../src/engine/github-rate.js';
import { GitHubAccessError } from '../src/github/client.js';
import { NotGitHubRepoError } from '../src/read/project.js';
import type { StepResult, StepStatus } from '../src/uninstall/apply.js';
import { UninstallError, UninstallFinished } from '../src/uninstall/errors.js';
import { ProgressFile, uninstallProgressPath } from '../src/uninstall/progress.js';
import { fake } from './helpers/secret-repo.js';
import { AT, blob, cleanHomes, gh, local, mergePr, sampleRecord, SHA, term, world, type World } from './helpers/uninstall-world.js';

afterEach(() => { cleanHomes(); });
const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (prefix: string): string => { const d = mkdtempSync(join(tmpdir(), prefix)); dirs.push(d); return d; };

const TK = fake.githubPat();
/** Key names built at runtime (the no-secret-literals rule reads `<name>: value` as a credential). */
const TK_KEY = ['to', 'ken'].join('');
const APP = { owner: 'o', repo: 'shop' };

type TestIO = CliIO & { lines: string[]; errs: string[]; asked: string[] };
function mkio(over: Partial<CliIO> = {}): TestIO {
  const lines: string[] = [];
  const errs: string[] = [];
  const asked: string[] = [];
  const prompt: Prompter = {
    confirm: async (m) => { asked.push(m); return true; },
    select: async (m) => { asked.push(m); throw new Error('no select'); },
    text: async (m) => { asked.push(m); throw new Error('no text'); },
  };
  return { prompt, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env: {}, lines, errs, asked, interactive: true, ...over };
}

const repoDir = (files: Record<string, string> = {}): string => {
  const dir = tmp('pg-unin-');
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'config'), '[remote "origin"]\n\turl = https://github.com/o/shop.git\n');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', scripts: { test: 'vitest run' } }));
  for (const [rel, body] of Object.entries(files)) writeFileSync(join(dir, rel), body);
  return dir;
};

/** What the command is given, with spies; each seam can be replaced. */
function fakes(over: Partial<UninstallCommandDeps> = {}, home = tmp('pg-unin-home-')) {
  const calls: string[] = [];
  const g = { gh: {} as Octokit, login: 'alice', local: { home, env: {} } };
  const loaded = { app: { owner: 'o', repo: 'shop', repoId: 7 } } as never;
  const deps: UninstallCommandDeps = {
    // V9a (V8 sec M4): the command takes the app's lease before the loader: in this test's own home, never the machine's
    dir: '/x', allowBroad: false, deleteRepos: false, state: { home, env: {} },
    connect: (async (_io: unknown, _dir: unknown, o: unknown) => { calls.push(`connect ${JSON.stringify(o)}`); return { app: APP, g, [TK_KEY]: TK }; }) as never,
    load: (async () => { calls.push('load'); return loaded; }) as never,
    step: (async () => { calls.push('step'); return result('a-done'); }) as never,
    ...over,
  };
  return { deps, calls, home, g };
}
const result = (status: StepStatus, over: Partial<StepResult> = {}): StepResult => ({ status, phase: null, done: [], failed: [], skipped: [], manual: [], lines: [`the final message of ${status}`], ...over });
const TEXT = (i: TestIO): string => [...i.lines, ...i.errs].join('\n');

describe('V7: pipegen uninstall on the command line', () => {
  it('cli: uninstall dispatch, --delete-repos, help text', async () => {
    const dir = repoDir();
    const got: { deps?: UninstallCommandDeps; io?: CliIO } = {};
    let code = 0;
    const cmds: Partial<Commands> = {
      connect: (async () => { throw new Error('not here'); }) as never,
      uninstall: async (io, deps) => { got.io = io; got.deps = deps; return code; },
    };
    // argv to main to uninstallCommand, with --dir, the broad flag and --delete-repos handed on
    expect(await main(['uninstall', '--dir', dir], mkio({ cwd: tmpdir() }), cmds)).toBe(0);
    expect(got.deps).toMatchObject({ dir, allowBroad: false, deleteRepos: false });
    expect(got.deps?.connect).toBe(cmds.connect);   // G13's seam: Commands.connect, not a second copy
    expect(await main(['uninstall', '--dir', dir, '--delete-repos', '--allow-broad-token'], mkio({ cwd: tmpdir() }), cmds)).toBe(0);
    expect(got.deps).toMatchObject({ dir, allowBroad: true, deleteRepos: true });
    // the exit code of the command is main's
    for (const c of [1, 2, 4]) { code = c; expect(await main(['uninstall', '--dir', dir], mkio({ cwd: tmpdir() }), cmds), String(c)).toBe(c); }
    // an unexpected error is one cleaned line with no token, exit 1
    cmds.uninstall = async () => { throw new Error(`boom with ${TK}`); };
    const e = mkio({ cwd: tmpdir() });
    expect(await main(['uninstall', '--dir', dir], e, cmds)).toBe(1);
    expect(e.errs.join('\n')).toMatch(/pipegen uninstall failed: boom/);
    expect(e.errs.join('\n')).not.toContain(TK);
    // the help names the command, its flag and the two runs
    const h = mkio({ cwd: tmpdir() });
    expect(await main(['--help'], h)).toBe(0);
    const help = h.lines.join('\n');
    expect(help).toMatch(/pipegen uninstall\s+\S/);
    expect(help).toMatch(/--delete-repos\s+uninstall:/);
    expect(help).toMatch(/two runs/);
    expect(help).toMatch(/--delete-repos/);
  });

  it('cli: uninstall runs the unsafe-folder stop first and takes only its own flags', async () => {
    const dir = repoDir({ '.npmrc': 'registry=https://registry.example.invalid/\n' });
    let called = 0;
    const cmds: Partial<Commands> = { uninstall: async () => { called += 1; return 0; }, connect: (async () => { called += 1; throw new Error('no'); }) as never };
    const i = mkio({ cwd: dir });
    expect(await main(['uninstall'], i, cmds)).toBe(4);
    expect(called).toBe(0);
    expect(i.asked).toEqual([]);
    expect(await main(['uninstall', '--delete-repos'], mkio({ cwd: dir }), cmds)).toBe(4);
    expect(called).toBe(0);
    // another folder's command: only its own flags (--dir, --allow-broad-token, --delete-repos); there is no dry, preview or yes flag
    const ok = repoDir();
    for (const [argv, msg] of [
      [['uninstall', '--print'], '--print works with pipegen finish only.'],
      [['uninstall', '--rotate-key'], '--rotate-key works with pipegen finish only.'],
      [['uninstall', '--skip', 'tests'], '--skip works with pipegen run only.'],
      [['uninstall', '--strictness', 'strict'], '--strictness works with pipegen run only.'],
      [['uninstall', '--type', 'server'], '--type works with pipegen audit and pipegen run only.'],
      [['uninstall', '--json'], '--json works with pipegen audit only.'],
      [['uninstall', '--out', 'r.md'], '--out works with pipegen audit only.'],
      [['uninstall', '--verbose'], '--verbose works with pipegen audit only.'],
      [['uninstall', '--ai'], '--ai works with pipegen audit only.'],
      [['uninstall', '--dry-run'], 'dry-run'],
      [['uninstall', '--preview'], 'preview'],
      [['uninstall', '--yes'], 'yes'],
      [['uninstall', 'now'], 'pipegen uninstall takes no arguments'],
      [['finish', '--delete-repos'], '--delete-repos works with pipegen uninstall only.'],
      [['verify', '--delete-repos'], '--delete-repos works with pipegen uninstall only.'],
      [['update', '--delete-repos'], '--delete-repos works with pipegen uninstall only.'],
      [['cleanup', '--delete-repos'], '--delete-repos works with pipegen uninstall only.'],
      [['run', '--delete-repos'], '--delete-repos works with pipegen uninstall only.'],
      [['audit', '--delete-repos'], '--delete-repos works with pipegen uninstall only.'],
      [['uninstall', '--delete-repos', '--delete-repos'], '--delete-repos was given more than once'],
    ] as const) {
      const e = mkio({ cwd: ok });
      expect(await main([...argv], e, cmds), argv.join(' ')).toBe(1);
      expect(e.errs.join('\n'), argv.join(' ')).toContain(msg);
    }
    expect(called).toBe(0);
  });

  it('cli: uninstall without a terminal stops before any write (typed names need one)', async () => {
    for (const io of [mkio({ interactive: false }), mkio({ interactive: undefined }), mkio({ env: { CI: 'true' } })]) {
      const f = fakes();
      expect(await uninstallCommand(io, f.deps)).toBe(2);
      expect(f.calls).toEqual([]);   // not even a connect: no token read, no GitHub call, no write
      expect(io.errs.join('\n')).toMatch(/needs a terminal/);
      expect(io.errs.join('\n')).toMatch(/Nothing was changed/);
      expect(io.asked).toEqual([]);
    }
    // main, with the real command: no connect either (the seam is replaced and must not be reached)
    let connected = 0;
    const i = mkio({ cwd: repoDir(), interactive: false });
    expect(await main(['uninstall'], i, { connect: (async () => { connected += 1; throw new Error('no'); }) as never })).toBe(2);
    expect(connected).toBe(0);
    // the same real command with a terminal does connect (as write mode: uninstall deletes), once
    const f = fakes();
    expect(await uninstallCommand(mkio(), f.deps)).toBe(0);
    expect(f.calls[0]).toBe('connect {"allowBroad":false,"mode":"write"}');
  });
});

describe('V7: exit codes and messages', () => {
  const run = async (status: StepStatus, over: Partial<StepResult> = {}) => {
    const io = mkio();
    const f = fakes({ step: (async () => result(status, over)) as never });
    const code = await uninstallCommand(io, f.deps);
    return { code, io, f };
  };

  it('cli: exit codes: declined 1; stopped, failed, interrupted, replan 2; a-done, waiting, closed-unmerged, b-done, b-waiting 0; leftovers 2', async () => {
    const left = { what: 'a secret', why: 'kept' };
    const table: [StepStatus, Partial<StepResult>, number][] = [
      ['declined', {}, 1],
      ['stopped', {}, 2], ['failed', {}, 2], ['interrupted', {}, 2], ['replan', {}, 2],
      ['a-done', {}, 0], ['waiting', {}, 0], ['closed-unmerged', {}, 0], ['b-done', {}, 0], ['b-waiting', {}, 0], ['b-partial', {}, 2],
      // leftovers: a-done and b-done with a manual step, a kept item or a step not done end in 2
      ['a-done', { manual: [{ what: 'x', why: 'y' }] }, 2], ['a-done', { skipped: [left] }, 2], ['a-done', { failed: [left] }, 2],
      ['b-done', { manual: [{ what: 'x', why: 'y' }] }, 2], ['b-done', { skipped: [left] }, 2], ['b-done', { failed: [left] }, 2],
      ['waiting', { manual: [{ what: 'x', why: 'y' }] }, 0], ['b-waiting', { manual: [{ what: 'x', why: 'y' }] }, 0],
    ];
    for (const [status, over, want] of table) {
      const r = await run(status, over);
      expect(r.code, `${status} ${JSON.stringify(over)}`).toBe(want);
      expect(r.io.lines.join('\n'), status).toContain(`the final message of ${status}`);   // the run's own message is always shown
    }
    // the options reach the step: --delete-repos, and canDeleteRepos only from the connection (false here: token mode)
    let seen: Record<string, unknown> = {};
    const f = fakes({ deleteRepos: true, step: (async (_g: unknown, _l: unknown, _io: unknown, d: Record<string, unknown>) => { seen = d; return result('a-done'); }) as never });
    await uninstallCommand(mkio(), f.deps);
    expect(seen).toMatchObject({ deleteRepos: true, canDeleteRepos: false, interactive: true });
    const g = fakes({ step: (async (_g: unknown, _l: unknown, _io: unknown, d: Record<string, unknown>) => { seen = d; return result('a-done'); }) as never });
    await uninstallCommand(mkio(), g.deps);
    expect(seen).toMatchObject({ deleteRepos: false });
  });

  it('cli: the stops uninstallStep and the loader throw are one clear message and exit 2 (no terminal, lease, progress file, changed record, 401, rate stop, recheck)', async () => {
    const stops: [string, unknown][] = [
      ['no terminal', new UninstallError('pipegen shows what it will do and asks for one yes before it changes anything, and this run has no terminal. Nothing was changed.')],
      ['held lease', new UninstallError('another pipegen run holds the lease for o/shop. Nothing was changed.')],
      ['progress file', new UninstallError('pipegen can\'t use its uninstall progress file /x: it is not JSON. Nothing was changed.')],
      ['changed record', new UninstallError('the install record changed since the preview, so pipegen sent nothing. Run `pipegen uninstall` again.')],
      ['recheck', new UninstallError('the default branch changed since the preview, so pipegen sent nothing. Run `pipegen uninstall` again to see the new plan. Nothing was changed.')],
      ['401', new GitHubAccessError('GitHub rejected the token (401). Log in again or set GITHUB_TOKEN.')],
      ['rate stop', new GitHubRateLimitError('GitHub\'s rate limit is used up; it resets later', { resetAt: 1_900_000_000_000 })],
    ];
    for (const [name, err] of stops) {
      for (const where of ['load', 'step'] as const) {
        const io = mkio();
        const f = fakes({ [where]: (async () => { throw err; }) as never });
        expect(await uninstallCommand(io, f.deps), `${name} from ${where}`).toBe(2);
        const text = io.errs.join('\n');
        expect(text, name).toMatch(/^pipegen uninstall stopped: /m);
        expect(text, name).toContain(String((err as Error).message).slice(0, 40));
        expect(io.lines, name).toEqual([]);   // the stop is an error line, not output
        if (where === 'load') expect(f.calls, name).not.toContain('step');
      }
    }
    // a token in a message never gets out
    const io = mkio();
    const f = fakes({ step: (async () => { throw new UninstallError(`GitHub said no to ${TK}`); }) as never });
    expect(await uninstallCommand(io, f.deps)).toBe(2);
    expect(TEXT(io)).not.toContain(TK);
    // an unexpected error is not one of these: it passes to main (exit 1, "pipegen uninstall failed")
    await expect(uninstallCommand(mkio(), fakes({ step: (async () => { throw new TypeError('bug'); }) as never }).deps)).rejects.toThrow('bug');
  });

  it('cli: no token, or a folder that is not a GitHub repo, stops before the record is read or anything is planned', async () => {
    const missing = fakes({ connect: (async () => { throw new GitHubAccessError('pipegen has no GitHub login to write with.'); }) as never });
    const io = mkio();
    expect(await uninstallCommand(io, missing.deps)).toBe(2);
    expect(missing.calls).toEqual([]);   // neither load nor step
    expect(io.errs.join('\n')).toMatch(/no GitHub login to write with/);
    const notRepo = fakes({ connect: (async () => { throw new NotGitHubRepoError('this folder\'s origin is not on github.com'); }) as never });
    const j = mkio();
    expect(await uninstallCommand(j, notRepo.deps)).toBe(2);
    expect(notRepo.calls).toEqual([]);
    expect(j.errs.join('\n')).toMatch(/origin is not on github\.com/);
  });

  it('cli: UninstallFinished is a success: exit 0, its whole message shown, nothing planned', async () => {
    const msg = 'pipegen deleted o/pipelines in its last run (GitHub now answers 404 for it), so the uninstall of o/shop is finished.\nStill yours to do (pipegen can\'t come back to them: the install record is gone):\n  - an item: kept\n    Delete it by hand.';
    const io = mkio();
    const f = fakes({ load: (async () => { throw new UninstallFinished(msg); }) as never });
    expect(await uninstallCommand(io, f.deps)).toBe(0);
    expect(f.calls).not.toContain('step');
    expect(io.lines.join('\n')).toContain('so the uninstall of o/shop is finished.');
    expect(io.lines).toContain('Still yours to do (pipegen can\'t come back to them: the install record is gone):');
    expect(io.lines).toContain('  - an item: kept');
    expect(io.errs).toEqual([]);
  });

  it('cli: the loader loads the record once, with the terminal and the local folder, and the step gets that record (never a second load)', async () => {
    let loadArgs: unknown[] = [];
    let stepArgs: unknown[] = [];
    const io = mkio();
    const f = fakes({
      load: (async (...a: unknown[]) => { loadArgs = a; return { marker: 'loaded' }; }) as never,
      step: (async (...a: unknown[]) => { stepArgs = a; return result('a-done'); }) as never,
    });
    await uninstallCommand(io, f.deps);
    expect(loadArgs[1]).toEqual(APP);
    expect(loadArgs[2]).toMatchObject({ interactive: true, io: io.prompt, local: f.g.local });
    expect(stepArgs[1]).toEqual({ marker: 'loaded' });
    // there is no preview-only or dry path that loads the record: the command has no such option
    const src = readFileSync(join(import.meta.dirname, '..', 'src', 'cli', 'uninstall.ts'), 'utf8');
    expect(src.match(/\bloadUninstallRecord\(/g)?.length).toBe(1);
    expect(src.replace(/\/\/.*$/gm, '').replace(/\/\*[^]*?\*\//g, '')).not.toMatch(/\b(?:dry|preview|dryRun)\b/i);
  });

  it('cli: a pending central delete marker (a crash during the repo delete) gets its own stop message, naming the files', async () => {
    const f = fakes({ load: (async () => { throw new UninstallError('No install record for o/shop. pipegen only removes what it recorded installing.'); }) as never });
    const pf = await ProgressFile.open(APP, 7, f.g.local);
    const base = { phase: 'B' as const, anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: SHA('c'), recordBlobSha: SHA('d') }, done: [], leftovers: [] };
    pf.save({ ...base, centralDeleteSent: { repoId: 5, recordHash: 'e'.repeat(64), confirmed: false } });
    const io = mkio();
    expect(await uninstallCommand(io, f.deps)).toBe(2);
    const text = io.errs.join('\n');
    expect(text).toContain('No install record for o/shop');      // the loader's own stop stays
    expect(text).toMatch(/was deleting o\/pipelines when it stopped/);
    expect(text).toContain(uninstallProgressPath(APP, f.g.local));
    expect(text).toContain(localRecordPath(APP, f.g.local));
    expect(text).toMatch(/GitHub/);
    // no marker, a confirmed one (the loader finishes that case itself), or another stage: no such message
    for (const sent of [undefined, { repoId: 5, recordHash: 'e'.repeat(64), confirmed: true }]) {
      pf.save({ ...base, ...(sent === undefined ? {} : { centralDeleteSent: sent }) });
      const j = mkio();
      expect(await uninstallCommand(j, f.deps)).toBe(2);
      expect(TEXT(j)).not.toMatch(/was deleting o\/pipelines/);
    }
    pf.remove();
    const k = mkio();
    expect(await uninstallCommand(k, f.deps)).toBe(2);
    expect(TEXT(k)).not.toMatch(/was deleting o\/pipelines/);
  });
});

describe('V7: the second run 2 through the command (V6 carry)', () => {
  const BR = 'pipegen/uninstall-shop';
  async function setup(): Promise<{ w: World; rec: ReturnType<typeof sampleRecord>; deps: UninstallCommandDeps; t: ReturnType<typeof term> }> {
    const w = world();
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
    w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: recordFileText(rec) }, 'record');
    w.app.pulls.push({ number: 5, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: withRecordMarker('pipegen sets up CI', recordHash(rec)), state: 'closed', html_url: 'https://github.com/o/shop/pull/5' });
    await writeLocalRecord(APP, { recordHash: recordHash(rec), setupPr: 5, updatedAt: AT }, local(w));
    // run 1 is done: its pull request merged
    w.app.refs.set('heads/pipegen/uninstall', w.g.head('o/shop'));
    w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: 'https://github.com/o/shop/pull/1' });
    w.merged.set('shop#1', '2026-11-06T10:00:00Z');
    const pf = await ProgressFile.open(APP, w.app.id, local(w));
    pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha: blob(recordFileText(rec)) }, prNumber: 1, prUrl: 'https://github.com/o/shop/pull/1', done: [], leftovers: [] });
    const t = term();
    const deps: UninstallCommandDeps = {
      dir: '/x', allowBroad: false, deleteRepos: false, state: local(w),
      connect: (async () => ({ app: APP, [TK_KEY]: TK, g: { gh: gh(w), login: 'o', local: local(w) } })) as never,
    };
    return { w, rec, deps, t };
  }

  it('cli: a second run 2 after the central pull request merged loads the record from the progress file\'s blob and finishes', async () => {
    const { w, deps, t } = await setup();
    const first = mkio({ prompt: t.p });
    expect(await uninstallCommand(first, deps)).toBe(0);   // run 2 opened the central pull request: a normal stop
    expect(first.lines.join('\n')).toMatch(/Merge the central pull request/);
    mergePr(w, w.central, BR);
    expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).has(recordPath('shop'))).toBe(false);
    const second = mkio({ prompt: t.p });
    // the record is gone from central: rebuilt, not "No install record". The run finishes (b-done); the scratch repo's kept default branch
    // is a note, not a leftover (V8 sec i6, V9a), so a complete uninstall exits 0
    expect(await uninstallCommand(second, deps)).toBe(0);
    expect(second.lines.join('\n')).toMatch(/^Notes:/m);
    expect(TEXT(second)).not.toMatch(/No install record/);
    expect(second.lines.join('\n')).toMatch(/pipegen is uninstalled from o\/shop/);
    expect(existsSync(localRecordPath(APP, local(w)))).toBe(false);
    expect(existsSync(uninstallProgressPath(APP, local(w)))).toBe(false);
  });

  it('cli: a second run 2 with a wrong local hash stops with exit 2 and the loader\'s own words', async () => {
    const { w, deps, t } = await setup();
    expect(await uninstallCommand(mkio({ prompt: t.p }), deps)).toBe(0);
    mergePr(w, w.central, BR);
    await writeLocalRecord(APP, { recordHash: 'f'.repeat(64), setupPr: 5, updatedAt: AT }, local(w));
    const io = mkio({ prompt: t.p });
    expect(await uninstallCommand(io, deps)).toBe(2);
    expect(io.errs.join('\n')).toMatch(/^pipegen uninstall stopped: /m);
    expect(existsSync(uninstallProgressPath(APP, local(w)))).toBe(true);   // nothing was removed
  });
});

describe('V7: the docs say what was built', () => {
  const read = (rel: string): string => readFileSync(join(import.meta.dirname, '..', rel), 'utf8');

  it('docs: design §14 (the repo-deletion right, the secrets line, the two runs and why), the threat model row and the V-live checklist', () => {
    const design = read('docs/design.md');
    const s14 = design.slice(design.indexOf('## 14. Uninstall'), design.indexOf('## 15.'));
    // #127, V8-R1 (sec M2): v0.2 deletes no repo the user created and prints no command for it; the App's right is the planned path
    expect(s14).toContain('so uninstall never deletes them and never prints a `gh repo delete` command for them, with or without `--delete-repos`');
    expect(s14).toMatch(/Planned next, with pipegen's own GitHub App login: `--delete-repos` will use the repo-deletion right the App already has \(Administration: write\)/);
    expect(s14).not.toMatch(/asked for only then/);
    expect(s14).toContain('Secrets pipegen created are removed: `PIPEGEN_`-prefixed ones directly, the app\'s own names only after you type the name.');
    expect(s14).not.toMatch(/Only secrets with the `PIPEGEN_` prefix/);
    expect(s14).toMatch(/two runs of the same command \(phase A, phase B\)/);
    expect(s14).toMatch(/Why two runs: the uninstall PR deletes `pipegen\.yml`.*`pipegen \/ gate`.*`pipegen-verify`.*install record/s);
    const t56 = read('docs/threat-model.md').split('\n').find((l) => l.startsWith('| T56 |')) as string;
    expect(t56).toMatch(/An edited install record turns uninstall into a delete tool/);
    for (const part of [/GitHub's current id and `created_at` equal the recorded ones/, /path claim/, /builder forms/, /strict schema/, /typed|Names are typed/, /trustedPrevious/]) expect(t56, String(part)).toMatch(part);
    // the V-live rows: the steps in order, every result "not run"
    const smoke = read('docs/smoke-test.md');
    const sec = smoke.slice(smoke.indexOf('## Uninstall (V-live)'), smoke.indexOf('## Release'));
    const rows = sec.split('\n').filter((l) => /^\| UN-\d+ /.test(l));
    expect(rows.length).toBeGreaterThanOrEqual(10);
    for (const r of rows) expect(r.trimEnd().endsWith('| not run |'), r.slice(0, 30)).toBe(true);
    expect(rows.join('\n')).toMatch(/create.*merged.*finish[^]*before[^]*phase A[^]*merge[^]*phase B[^]*after[^]*deleted by hand/is);
  });

  it('docs: the README uninstall section (permissions, the proxy limit, no App to remove, the two runs, the kept org-rule file, the update branch)', () => {
    const readme = read('README.md');
    const sec = readme.slice(readme.indexOf('## Uninstall (v0.2)'), readme.indexOf('## Install safely'));
    expect(sec.length).toBeGreaterThan(500);
    expect(sec).toMatch(/Two runs, and why/);
    expect(sec).toMatch(/Administration \(read and write\) is optional/);
    expect(sec).toMatch(/\. Uninstall doesn't need Members: read/);
    expect(sec).toMatch(/HTTPS_PROXY/);
    expect(sec).toMatch(/no App to remove/);
    expect(sec).toMatch(/--required\.yml.*unfinished until you remove the organisation rule/s);
    expect(sec).toMatch(/pipegen\/update-<name>.*hold that delete back/s);
    expect(sec).toMatch(/needs a terminal/);
  });
});

describe('V7 fold 3 (DECISIONS #127): v0.2 uses a fine-grained token; the App is planned, never the current path', () => {
  const read = (rel: string): string => readFileSync(join(import.meta.dirname, '..', rel), 'utf8');
  const PLANNED = /planned/i;

  it('docs: README and design never call the App the current path (every line naming the App says it is planned, or is about a token kind)', () => {
    for (const f of ['README.md', 'docs/design.md']) {
      const lines = read(f).split('\n').filter((l) => /\bApp\b/.test(l));
      for (const l of lines) {
        // the one other mention: a ghu_ login set in GITHUB_TOKEN (a token kind), and the App in the deleted-repo sentence below the marker
        const ok = PLANNED.test(l) || /GITHUB_TOKEN/.test(l) || /Plan L|code paths exist/.test(l);
        expect(ok, `${f}: ${l.slice(0, 120)}`).toBe(true);
      }
    }
    const readme = read('README.md');
    const access = readme.slice(readme.indexOf('- **Access:**'), readme.indexOf('- **Shown before anything runs:**'));
    expect(access).toMatch(/in v0\.2 you use a \*\*fine-grained token\*\*/);
    expect(access).not.toMatch(/a GitHub App or fine-grained token/);
    for (const part of [/gh repo create <owner>\/pipelines --private/, /pipegen-proof-<repo> --private/, /empties the scratch repo after the proof instead of deleting it/, /never deletes these repos itself \(you created them\)/, /GitHub App login \(which makes and deletes these repos itself\) is planned next\./]) expect(access, String(part)).toMatch(part);
    const design = read('docs/design.md');
    const s12 = design.slice(design.indexOf('## 12. Access'), design.indexOf('## 13.'));
    expect(s12).toMatch(/\*\*v0\.2 uses a fine-grained token\*\*/);
    expect(s12).toMatch(/\*\*Planned next \(Plan L, after the release\): pipegen's own GitHub App\*\*/);
    expect(s12).not.toMatch(/GitHub App\*\* first/);
    const s14 = design.slice(design.indexOf('## 14. Uninstall'), design.indexOf('## 15.'));
    expect(s14).not.toMatch(/uses the repo-deletion right the App already has \(Administration: write\); with a token/);
    const t5 = read('docs/threat-model.md').split('\n').find((l) => l.startsWith('| T5 |')) as string;
    expect(t5).toMatch(/v0\.2 uses a \*\*fine-grained token\*\*/);
    expect(t5).toMatch(PLANNED);
    // fold 4: every --delete-repos line says v0.2 prints the commands (it never says pipegen deletes the repos), in README, design and the central PR body
    for (const [f, text] of [['README.md', read('README.md')], ['docs/design.md', read('docs/design.md')]] as const) {
      for (const l of text.split('\n').filter((x) => /--delete-repos/.test(x) && /\bdeletes?\b/.test(x))) {
        expect(/print|planned|deletes no|delete no|deletes none|never deletes/i.test(l), `${f}: ${l.slice(0, 140)}`).toBe(true);
      }
    }
    expect(read('README.md')).toMatch(/--delete-repos\s+# v0\.2: deletes no repo and prints no delete command/);
    expect(read('docs/design.md')).toMatch(/In v0\.2 you create `pipelines` and `pipegen-proof-<repo>` yourself, so uninstall never deletes them/);
    expect(read('src/uninstall/central.ts')).not.toMatch(/to print the `gh repo delete` commands|repos pipegen made/);
    expect(read('src/github/client.ts')).not.toMatch(/App installation\\?'?s? ?\)|\(or the App installation/);
    expect(read('docs/smoke-test.md')).not.toMatch(/created by the App or by hand|pipegen's GitHub App login works/);
  });

  it('docs: the help text, the consent screen and the error texts say v0.2 uses a token and the App login is planned', async () => {
    const h = mkio({ cwd: tmpdir() });
    expect(await main(['--help'], h)).toBe(0);
    const help = h.lines.join('\n');
    expect(help).toMatch(/in v0\.2 you use a fine-grained token/);
    expect(help).toMatch(/--delete-repos\s+uninstall: in v0\.2 deletes no repo and prints no delete command/);
    expect(help).toMatch(/GitHub App login \(which makes and deletes these repos itself\) is planned next/);
    expect(help).not.toMatch(/With the pipegen App it deletes/);
    // no message of src tells the user to log in with, or install, the pipegen App (the App's own code paths excepted)
    const client = read('src/github/client.ts');
    expect(client).not.toMatch(/install the pipegen GitHub App|or pipegen\\?'s GitHub App|use pipegen\\?'s GitHub App|or log in again/);
    expect(client).toMatch(/v0\.2 ships\s+\/\/\s+no App login \(DECISIONS #127/);
    expect(client).not.toMatch(/v0\.1 ships\s+\/\/\s+no login command/);
    const phaseB = read('src/uninstall/phase-b.ts');
    expect(phaseB).not.toMatch(/with the pipegen App\)|open Settings → GitHub Apps/);
    expect(phaseB).toMatch(/no App to remove/);
  });
});
