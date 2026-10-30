// v0.2 Plan D, D1: the created-file guard (preflight S3, S4 path part, B2). Real files in a temp folder: the repo tree is hostile.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { guardCreatedFiles, gitBlobSha, type BaseTree, type GuardCtx } from '../src/create/guard.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { CreatedFile, RepoProfile } from '../src/types.js';
import { profile, service } from './helpers/render.js';

const made: string[] = [];
afterEach(() => { for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true }); });
/** A repo folder holding `files` (path -> text). */
function repo(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-guard-'));
  made.push(dir);
  for (const [p, t] of Object.entries(files)) { mkdirSync(join(dir, dirname(p)), { recursive: true }); writeFileSync(join(dir, p), t); }
  return dir;
}
const base = (files: Record<string, string> = {}): BaseTree => new Map(Object.entries(files).map(([p, t]) => [p, { sha: gitBlobSha(t), read: async () => t }]));
const prof = (paths: string[] = ['.']): RepoProfile => ({ ...profile(paths.map((p, i) => service({ name: `s${i}`, path: p }))), repoFiles: emptyRepoFiles() });
const ctx = (root: string, over: Partial<GuardCtx> = {}): GuardCtx => ({ root, baseTree: base(), installRecord: null, profile: prof(), ...over });
const file = (path: string, content = 'x\n', over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'docker', reason: 't', repo: 'app', ...over });
const edit = (path: string, original: string, content: string, over: Partial<CreatedFile> = {}): CreatedFile => file(path, content, { part: 'tests', edited: { original }, ...over });
const reasons = async (files: CreatedFile[], c: GuardCtx): Promise<string> => (await guardCreatedFiles(files, c)).refused.map((r) => `${r.path}: ${r.reason}`).join(' | ');
const okPaths = async (files: CreatedFile[], c: GuardCtx): Promise<string[]> => (await guardCreatedFiles(files, c)).ok.map((f) => f.path);

const PJ = JSON.stringify({ name: 'app', version: '1.0.0', scripts: { build: 'tsc' }, devDependencies: { typescript: '5.6.0' } }, null, 2);
const PJ_NEW = JSON.stringify({ name: 'app', version: '1.0.0', scripts: { build: 'tsc', test: 'vitest run' }, devDependencies: { typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5', c8: '12.0.0' } }, null, 2);

describe('guard: new files', () => {
  it('a new Dockerfile is ok; the guard writes nothing', async () => {
    const root = repo({ 'package.json': PJ });
    const r = await guardCreatedFiles([file('Dockerfile', 'FROM x\n')], ctx(root));
    expect(r.ok.map((f) => f.path)).toEqual(['Dockerfile']);
    expect(r.refused).toEqual([]);
    const { readdirSync } = await import('node:fs');
    expect(readdirSync(root).sort()).toEqual(['package.json']);
  });
  it('a new file in a folder that does not exist yet is ok', async () => {
    expect(await okPaths([file('api/Dockerfile'), file('api/.dockerignore')], ctx(repo(), { profile: prof(['api']) }))).toEqual(['api/Dockerfile', 'api/.dockerignore']);
  });
  it('a path the path rule refuses is refused with its reason (every producer, no matter the caller)', async () => {
    const c = ctx(repo());
    for (const p of ['../x', '/etc/x', 'a/../b', '.git/hooks/pre-commit', 'a b', 'CON.txt', 'x\\y', '']) expect(await reasons([file(p)], c), p).toMatch(/refused|path/i);
  });
  it('a new file in the wrong repo is refused', async () => {
    expect(await reasons([file('Dockerfile', 'x', { repo: 'central' })], ctx(repo()))).toMatch(/central/);
    expect(await okPaths([file('a.txt', 'x', { repo: 'central' })], ctx(repo(), { repo: 'central' }))).toEqual(['a.txt']);
  });
  it('new app source (a code file in a service folder that is not a test and has no registry rule) is refused', async () => {
    const c = ctx(repo(), { profile: prof(['.', 'api']) });
    expect(await reasons([file('src/helper.ts')], c)).toMatch(/source code/);
    expect(await reasons([file('api/src/x.py')], c)).toMatch(/source code/);
    expect(await reasons([file('app.js')], c)).toMatch(/source code/);
    // a starter test (a registry rule claims it) and non-code files are not app source
    expect(await okPaths([file('api/test/smoke.test.ts', 'x', { part: 'tests' }), file('api/README.md'), file('api/Dockerfile')], c)).toEqual(['api/test/smoke.test.ts', 'api/README.md', 'api/Dockerfile']);
    // outside every service folder it is not "app source" (the registry decides)
    expect(await okPaths([file('tools/x.ts')], ctx(repo(), { profile: prof(['api']) }))).toEqual(['tools/x.ts']);
  });
});

describe('guard: create-only (#97)', () => {
  it('a path that exists on disk is refused, with the user\'s work named', async () => {
    const root = repo({ Dockerfile: 'FROM mine\n' });
    expect(await reasons([file('Dockerfile', 'FROM x\n')], ctx(root))).toMatch(/already exists.*never overwrites/);
  });
  it('a path that exists in the delivery base tree only is refused', async () => {
    const c = ctx(repo(), { baseTree: base({ Dockerfile: 'FROM theirs\n' }) });
    expect(await reasons([file('Dockerfile')], c)).toMatch(/default branch|delivery/);
  });
  it('overwriting an existing test file is refused (no migration in v0.2)', async () => {
    const root = repo({ 'test/a.test.ts': 'old' });
    expect(await reasons([file('test/a.test.ts', 'new', { part: 'tests' })], ctx(root))).toMatch(/already exists/);
  });
  it('an existing Dockerfile is never edited (an edit marker does not help: no rule edits it)', async () => {
    const root = repo({ Dockerfile: 'FROM mine\n' });
    const f = file('Dockerfile', 'FROM mine\nUSER 1\n', { edited: { original: 'FROM mine\n' } });
    expect(await reasons([f], ctx(root, { baseTree: base({ Dockerfile: 'FROM mine\n' }) }))).toMatch(/does not edit/);
  });
  it('an edit to existing app source is refused', async () => {
    const root = repo({ 'src/app.ts': 'a' });
    const f = file('src/app.ts', 'b', { part: 'tests', edited: { original: 'a' } });
    expect(await reasons([f], ctx(root, { baseTree: base({ 'src/app.ts': 'a' }) }))).toMatch(/does not edit/);
  });
  it('an existing .dockerignore is not overwritten', async () => {
    const root = repo({ '.dockerignore': 'x' });
    expect(await reasons([file('.dockerignore')], ctx(root))).toMatch(/already exists/);
  });
});

describe('guard: edits through edited.original', () => {
  it('original equal to disk and base tree: ok', async () => {
    const root = repo({ 'package.json': PJ });
    const c = ctx(root, { baseTree: base({ 'package.json': PJ }) });
    expect(await okPaths([edit('package.json', PJ, PJ_NEW, { needsConfirm: true })], c)).toEqual(['package.json']);
  });
  it('original different from the disk: refused', async () => {
    const root = repo({ 'package.json': `${PJ}\n` });
    const c = ctx(root, { baseTree: base({ 'package.json': PJ }) });
    expect(await reasons([edit('package.json', PJ, PJ_NEW)], c)).toMatch(/differs from .* on your disk/);
  });
  it('a base tree that differs from the disk: refused either way', async () => {
    const root = repo({ 'package.json': PJ });
    expect(await reasons([edit('package.json', PJ, PJ_NEW)], ctx(root, { baseTree: base({ 'package.json': `${PJ} ` }) }))).toMatch(/differs from .* on the default branch/);
    expect(await reasons([edit('package.json', PJ, PJ_NEW)], ctx(root, { baseTree: base({ 'package.json': PJ.replace('1.0.0', '2.0.0') }) }))).toMatch(/differs from .* on the default branch/);
  });
  it('an edit of a file that is on the disk only, or in the base tree only: refused (it must be on both)', async () => {
    expect(await reasons([edit('package.json', PJ, PJ_NEW)], ctx(repo({ 'package.json': PJ })))).toMatch(/in your local folder but not on the default branch/);
    expect(await reasons([edit('package.json', PJ, PJ_NEW)], ctx(repo(), { baseTree: base({ 'package.json': PJ }) }))).toMatch(/on the default branch but not in your local folder/);
  });
  it('an edit with a non-empty original of a file that exists nowhere is refused; an empty original makes a new file', async () => {
    expect(await reasons([edit('CODEOWNERS', 'x', 'y', { part: 'codeowners' })], ctx(repo()))).toMatch(/does not exist/);
    expect(await okPaths([edit('CODEOWNERS', '', '# x\n', { part: 'codeowners' })], ctx(repo()))).toEqual(['CODEOWNERS']);
  });
  it('package.json and package-lock.json must exist: pipegen edits them, never creates them', async () => {
    expect(await reasons([edit('package.json', '', PJ_NEW)], ctx(repo()))).toMatch(/must already exist/);
  });
  it('an original that is not valid UTF-8 text on the disk is refused (the bytes can not be proven equal)', async () => {
    const root = repo();
    writeFileSync(join(root, 'CODEOWNERS'), Buffer.from([0x61, 0xff, 0x0a]));
    const t = Buffer.from([0x61, 0xff, 0x0a]).toString('utf8');
    expect(await reasons([edit('CODEOWNERS', t, `${t}x`, { part: 'codeowners' })], ctx(root, { baseTree: base({ CODEOWNERS: t }) }))).toMatch(/UTF-8|text/);
  });
  it('an edit on a binary or oversize file on the disk is refused; a FIFO is never opened', async () => {
    const root = repo();
    writeFileSync(join(root, 'CODEOWNERS'), Buffer.from([0x61, 0x00, 0x0a]));
    expect(await reasons([edit('CODEOWNERS', 'a\u0000\n', 'x', { part: 'codeowners' })], ctx(root, { baseTree: base({ CODEOWNERS: 'a\u0000\n' }) }))).toMatch(/binary|read/);
  });
  it('a base tree entry that can not be read as text, or a malformed marker, is refused', async () => {
    const root = repo({ CODEOWNERS: 'a\n' });
    const unreadable: BaseTree = new Map([['CODEOWNERS', { sha: gitBlobSha('a\n'), read: async () => null }]]);
    expect(await reasons([edit('CODEOWNERS', 'a\n', 'a\nb\n', { part: 'codeowners' })], ctx(root, { baseTree: unreadable }))).toMatch(/default branch could not be read/);
    const throwing: BaseTree = new Map([['CODEOWNERS', { sha: gitBlobSha('a\n'), read: async () => { throw new Error('boom'); } }]]);
    expect(await reasons([edit('CODEOWNERS', 'a\n', 'a\nb\n', { part: 'codeowners' })], ctx(root, { baseTree: throwing }))).toMatch(/default branch could not be read/);
    const bad = edit('CODEOWNERS', 'a\n', 'a\nb\n', { part: 'codeowners', edited: { original: 5 } as unknown as { original: string } });
    expect(await reasons([bad], ctx(repo(), {}))).toMatch(/malformed/);
  });
  it('an edit marker with both markers (edited and inserted) is refused', async () => {
    const root = repo({ CODEOWNERS: 'a\n' });
    const f = edit('CODEOWNERS', 'a\n', 'a\nb\n', { part: 'codeowners', inserted: { original: 'a\n', jobs: [], needs: [] } });
    expect(await reasons([f], ctx(root, { baseTree: base({ CODEOWNERS: 'a\n' }) }))).toMatch(/both/);
  });
  it('an edited workflow (inserted) needs allowWorkflowInsert; without it, refused', async () => {
    const wf = 'name: x\non: push\njobs: {}\n';
    const root = repo({ '.github/workflows/ci.yml': wf });
    const f = file('.github/workflows/ci.yml', `${wf}#`, { part: 'pipeline', inserted: { original: wf, jobs: [], needs: [] } });
    const c = ctx(root, { baseTree: base({ '.github/workflows/ci.yml': wf }) });
    expect(await reasons([f], c)).toMatch(/workflow/);
    expect(await okPaths([f], { ...c, allowWorkflowInsert: ['.github/workflows/ci.yml'] })).toEqual(['.github/workflows/ci.yml']);
    expect(await reasons([f], { ...c, allowWorkflowInsert: ['.github/workflows/other.yml'] })).toMatch(/workflow/);
  });
});

describe('guard: re-runs (#97), the install record', () => {
  const rec = (path: string, text: string, created = true) => ({ files: [{ path, part: 'docker' as const, sha: gitBlobSha(text), created }] });
  it('an owned file whose sha is unchanged is replaced', async () => {
    const root = repo({ Dockerfile: 'FROM old\n' });
    const c = ctx(root, { baseTree: base({ Dockerfile: 'FROM old\n' }), installRecord: rec('Dockerfile', 'FROM old\n') });
    const r = await guardCreatedFiles([file('Dockerfile', 'FROM new\n')], c);
    expect(r.ok.map((f) => f.path)).toEqual(['Dockerfile']);
    expect(r.notes.join(' ')).toMatch(/Dockerfile.*earlier|replac/);
  });
  it('an owner-edited file (disk sha differs) is kept, with a note: neither ok nor refused', async () => {
    const root = repo({ Dockerfile: 'FROM mine\n' });
    const c = ctx(root, { baseTree: base({ Dockerfile: 'FROM mine\n' }), installRecord: rec('Dockerfile', 'FROM old\n') });
    const r = await guardCreatedFiles([file('Dockerfile', 'FROM new\n')], c);
    expect(r.ok).toEqual([]);
    expect(r.refused).toEqual([]);
    expect(r.notes.join(' ')).toMatch(/Dockerfile.*(changed|kept|your)/i);
  });
  it('an owner-edited file in the base tree only is kept too', async () => {
    const root = repo({ Dockerfile: 'FROM old\n' });
    const c = ctx(root, { baseTree: base({ Dockerfile: 'FROM theirs\n' }), installRecord: rec('Dockerfile', 'FROM old\n') });
    const r = await guardCreatedFiles([file('Dockerfile')], c);
    expect(r.ok).toEqual([]);
    expect(r.notes.join(' ')).toMatch(/kept|changed/i);
  });
  it('owner-edited on the disk while the base tree still holds the recorded text: kept', async () => {
    const root = repo({ Dockerfile: 'FROM mine\n' });
    const c = ctx(root, { baseTree: base({ Dockerfile: 'FROM old\n' }), installRecord: rec('Dockerfile', 'FROM old\n') });
    const r = await guardCreatedFiles([file('Dockerfile')], c);
    expect(r.ok).toEqual([]);
    expect(r.notes.join(' ')).toMatch(/changed since/);
  });
  it('a file on the disk only (not in the base tree) that the record owns unchanged is replaced; changed, kept', async () => {
    const root = repo({ Dockerfile: 'FROM old\n' });
    expect(await okPaths([file('Dockerfile')], ctx(root, { installRecord: rec('Dockerfile', 'FROM old\n') }))).toEqual(['Dockerfile']);
    expect(await okPaths([file('Dockerfile')], ctx(repo({ Dockerfile: 'FROM mine\n' }), { installRecord: rec('Dockerfile', 'FROM old\n') }))).toEqual([]);
  });
  it('package.json and package-lock.json are never replaced as "owned": only an edit with its original, judged by B2', async () => {
    const root = repo({ 'package.json': PJ });
    const c = ctx(root, { baseTree: base({ 'package.json': PJ }), installRecord: { files: [{ path: 'package.json', part: 'tests', sha: gitBlobSha(PJ), created: true }] } });
    expect(await reasons([file('package.json', '{"scripts":{"build":"evil"}}', { part: 'tests' })], c)).toMatch(/already exists/);
  });
  it('a file the record lists as not created by pipegen, or not listed, is refused as any existing file', async () => {
    const root = repo({ Dockerfile: 'FROM old\n' });
    expect(await reasons([file('Dockerfile')], ctx(root, { installRecord: rec('Dockerfile', 'FROM old\n', false) }))).toMatch(/already exists/);
    expect(await reasons([file('Dockerfile')], ctx(root, { installRecord: rec('other', 'x') }))).toMatch(/already exists/);
    expect(await reasons([file('Dockerfile')], ctx(root, { installRecord: { files: [] } }))).toMatch(/already exists/);
  });
  it('an owned replacement still goes through the symlink and special-file checks', async () => {
    const root = repo({ real: 'FROM old\n' });
    symlinkSync(join(root, 'real'), join(root, 'Dockerfile'));
    expect(await reasons([file('Dockerfile')], ctx(root, { installRecord: rec('Dockerfile', 'FROM old\n') }))).toMatch(/symbolic link/);
  });
});

describe('guard: case clashes', () => {
  it('a path equal to an existing local path ignoring case is refused', async () => {
    const root = repo({ Dockerfile: 'x' });
    expect(await reasons([file('dockerfile')], ctx(root))).toMatch(/letter case/);
    expect(await reasons([file('DOCKERFILE')], ctx(root))).toMatch(/letter case/);
  });
  it('a folder that differs only in case is a clash', async () => {
    const root = repo({ 'Docs/a.md': 'x' });
    expect(await reasons([file('docs/new.md')], ctx(root))).toMatch(/letter case/);
  });
  it('a clash with a tracked path of the delivery base tree only is refused', async () => {
    const c = ctx(repo(), { baseTree: base({ 'API/Dockerfile': 'x', 'Readme.md': 'x' }) });
    expect(await reasons([file('api/Dockerfile'), file('README.md')], c)).toMatch(/letter case.*letter case|letter case/);
    expect((await guardCreatedFiles([file('api/Dockerfile'), file('README.md')], c)).ok).toEqual([]);
  });
  it('two created files in one batch that clash ignoring case, or where one is the folder of the other, are both refused', async () => {
    const c = ctx(repo());
    const r = await guardCreatedFiles([file('a/Dockerfile'), file('A/dockerfile'), file('x'), file('x/y')], c);
    expect(r.ok).toEqual([]);
    expect(r.refused.map((x) => x.path).sort()).toEqual(['A/dockerfile', 'a/Dockerfile', 'x', 'x/y']);
  });
});

describe('guard: files and folders', () => {
  it('a created path under an existing file is refused (local and base tree)', async () => {
    const root = repo({ api: 'a file' });
    expect(await reasons([file('api/Dockerfile')], ctx(root))).toMatch(/under.*file|is a file/);
    expect(await reasons([file('api/Dockerfile')], ctx(repo(), { baseTree: base({ api: 'a file' }) }))).toMatch(/under.*file|is a file/);
    expect(await reasons([file('a/b/c.txt')], ctx(repo({ 'a/b': 'file' })))).toMatch(/under.*file|is a file/);
  });
  it('a created path equal to an existing folder is refused (local and base tree)', async () => {
    const root = repo({ 'Dockerfile/x': 'a' });
    expect(await reasons([file('Dockerfile')], ctx(root))).toMatch(/folder/);
    expect(await reasons([file('Dockerfile')], ctx(repo(), { baseTree: base({ 'Dockerfile/x': 'a' }) }))).toMatch(/folder/);
    expect(await reasons([file('Dockerfile')], ctx(repo({ Dockerfile: '' }), { baseTree: base() }))).toMatch(/already exists/);
  });
  it('an empty local folder at the path is refused too', async () => {
    const root = repo();
    mkdirSync(join(root, 'Dockerfile'));
    expect(await reasons([file('Dockerfile')], ctx(root))).toMatch(/folder/);
  });
});

describe('guard: symlinks (lstat on every component, no realpath)', () => {
  it('a symlinked parent at each level is refused, to a folder inside or outside the repo', async () => {
    const outside = repo();
    const root = repo({ 'real/x': 'a', 'a/b/real': 'x' });
    mkdirSync(join(root, 'a/b/c'), { recursive: true });
    symlinkSync(outside, join(root, 'out'));
    symlinkSync(join(root, 'real'), join(root, 'in'));
    symlinkSync(outside, join(root, 'a/b/c/deep'));
    symlinkSync(outside, join(root, 'a/lnk'));
    const c = ctx(root);
    for (const p of ['out/Dockerfile', 'in/Dockerfile', 'a/b/c/deep/Dockerfile', 'a/lnk/x/y/Dockerfile']) expect(await reasons([file(p)], c), p).toMatch(/symbolic link/);
    expect(await okPaths([file('a/b/c/ok.txt')], c)).toEqual(['a/b/c/ok.txt']);
  });
  it('the final component as a symlink (file, folder, dangling) is refused, even when the target is missing', async () => {
    const root = repo({ real: 'x' });
    symlinkSync(join(root, 'real'), join(root, 'file-link'));
    symlinkSync(join(root, 'nowhere'), join(root, 'dangling'));
    mkdirSync(join(root, 'dir'));
    symlinkSync(join(root, 'dir'), join(root, 'dir-link'));
    for (const p of ['file-link', 'dangling', 'dir-link']) expect(await reasons([file(p)], ctx(root)), p).toMatch(/symbolic link/);
  });
  it('writing through a symlinked .github is refused', async () => {
    const outside = repo();
    const root = repo();
    symlinkSync(outside, join(root, '.github'));
    expect(await reasons([file('.github/workflows/pipegen.yml', 'name: x\n', { part: 'pipeline' })], ctx(root))).toMatch(/symbolic link/);
    expect(await reasons([file('.github/dependabot.yml', '', { part: 'pipeline', edited: { original: '' } })], ctx(root))).toMatch(/symbolic link/);
  });
  it('an edit of a symlinked file (CODEOWNERS) is refused', async () => {
    const root = repo({ real: 'a\n' });
    symlinkSync(join(root, 'real'), join(root, 'CODEOWNERS'));
    expect(await reasons([edit('CODEOWNERS', 'a\n', 'a\nb\n', { part: 'codeowners' })], ctx(root, { baseTree: base({ CODEOWNERS: 'a\n' }) }))).toMatch(/symbolic link/);
  });
  it('a symlinked repo root itself is allowed (the user opened the repo through a link); the check starts below it', async () => {
    const real = repo();
    const holder = repo();
    symlinkSync(real, join(holder, 'link'));
    expect(await okPaths([file('Dockerfile')], ctx(join(holder, 'link')))).toEqual(['Dockerfile']);
  });
  it('a root that is not a folder is refused with a reason', async () => {
    expect(await reasons([file('Dockerfile')], ctx(join(repo(), 'missing')))).toMatch(/repository folder|root/);
  });
});

describe('guard: special files', () => {
  it('a FIFO at the path is refused without being opened (an open would block)', async () => {
    const root = repo({ 'a/x': '1' });
    try { execFileSync('mkfifo', [join(root, 'Dockerfile')]); } catch { return; }   // no mkfifo here
    const t0 = Date.now();
    expect(await reasons([file('Dockerfile')], ctx(root))).toMatch(/not a regular file/);
    expect(await reasons([edit('Dockerfile', 'x', 'y', { part: 'docker' })], ctx(root, { baseTree: base({ Dockerfile: 'x' }) }))).toMatch(/not a regular file/);
    expect(Date.now() - t0).toBeLessThan(5000);
  });
  it('a FIFO as a parent folder is refused as a file, not a folder', async () => {
    const root = repo();
    try { execFileSync('mkfifo', [join(root, 'api')]); } catch { return; }
    expect(await reasons([file('api/Dockerfile')], ctx(root))).toMatch(/not a regular file|under/);
  });
});

describe('guard: v0.2 edits', () => {
  it('pyproject.toml and requirements-dev.txt, edited or created, anywhere, are refused', async () => {
    const root = repo({ 'pyproject.toml': 'a', 'requirements-dev.txt': 'b', 'api/pyproject.toml': 'c' });
    const b = base({ 'pyproject.toml': 'a', 'requirements-dev.txt': 'b', 'api/pyproject.toml': 'c' });
    const c = ctx(root, { baseTree: b });
    for (const p of ['pyproject.toml', 'requirements-dev.txt', 'api/pyproject.toml']) {
      expect(await reasons([edit(p, p === 'pyproject.toml' ? 'a' : p === 'requirements-dev.txt' ? 'b' : 'c', 'z')], c), p).toMatch(/Python/);
    }
    expect(await reasons([file('web/pyproject.toml'), file('web/Requirements-Dev.txt')], c)).toMatch(/Python.*Python/);
  });
});

describe('guard: package.json (B2)', () => {
  const run = async (next: object | string, original: string = PJ) => {
    const root = repo({ 'package.json': original });
    const content = typeof next === 'string' ? next : JSON.stringify(next, null, 2);
    return reasons([edit('package.json', original, content, { needsConfirm: true })], ctx(root, { baseTree: base({ 'package.json': original }) }));
  };
  const pj = JSON.parse(PJ) as Record<string, Record<string, string>>;
  it('the B2 additions with scripts.test are ok', async () => {
    expect(await run(PJ_NEW)).toBe('');
  });
  it('a change to scripts.build, a lifecycle script, c8/prettier/renovate or dependencies is refused', async () => {
    expect(await run({ ...pj, scripts: { build: 'x' } })).toMatch(/scripts\.build/);
    expect(await run({ ...pj, scripts: { ...pj.scripts, postinstall: 'x' } })).toMatch(/lifecycle/);
    expect(await run({ ...pj, c8: { lines: 1 } })).toMatch(/`c8`/);
    expect(await run({ ...pj, prettier: {} })).toMatch(/`prettier`/);
    expect(await run({ ...pj, renovate: {} })).toMatch(/`renovate`/);
    expect(await run({ ...pj, dependencies: { evil: '1.0.0' } })).toMatch(/dependencies/);
  });
  it('scripts.test only when absent or npm\'s default', async () => {
    const withJest = JSON.stringify({ ...pj, scripts: { ...pj.scripts, test: 'jest' } }, null, 2);
    expect(await run({ ...pj, scripts: { ...pj.scripts, test: 'vitest run' } }, withJest)).toMatch(/scripts\.test/);
    const dflt = JSON.stringify({ ...pj, scripts: { ...pj.scripts, test: 'echo "Error: no test specified" && exit 1' } }, null, 2);
    expect(await run({ ...pj, scripts: { ...pj.scripts, test: 'vitest run' } }, dflt)).toBe('');
  });
  it('devDependencies only from the B2 table at exact versions', async () => {
    expect(await run({ ...pj, devDependencies: { ...pj.devDependencies, vitest: '^5.0.5' } })).toMatch(/devDependencies/);
    expect(await run({ ...pj, devDependencies: { ...pj.devDependencies, eslint: '9.0.0' } })).toMatch(/devDependencies/);
    expect(await run({ ...pj, devDependencies: { ...pj.devDependencies, typescript: '5.7.0' } })).toMatch(/typescript/);
  });
  it('a package.json in a service folder is judged the same', async () => {
    const root = repo({ 'api/package.json': PJ });
    const c = ctx(root, { profile: prof(['api']), baseTree: base({ 'api/package.json': PJ }) });
    expect(await okPaths([edit('api/package.json', PJ, PJ_NEW, { needsConfirm: true })], c)).toEqual(['api/package.json']);
    expect(await reasons([edit('api/package.json', PJ, PJ_NEW.replace('tsc', 'evil'), { needsConfirm: true })], c)).toMatch(/scripts\.build/);
  });
});

describe('guard: package-lock.json (B2)', () => {
  const sri = (seed: string): string => `sha512-${createHash('sha512').update(seed).digest('base64')}`;
  const ent = (name: string, version: string, extra: object = {}): Record<string, unknown> => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name.slice(name.indexOf('/') + 1)}-${version}.tgz`, integrity: sri(`${name}@${version}`), ...extra });
  const lock = (dev: object, pkgs: object): string => JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'app', version: '1.0.0', devDependencies: dev }, ...pkgs } }, null, 2);
  const OLD = lock({ typescript: '5.6.0' }, { 'node_modules/typescript': ent('typescript', '5.6.0', { dev: true }) });
  const NEW = lock({ typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5', c8: '12.0.0' }, {
    'node_modules/typescript': ent('typescript', '5.6.0', { dev: true }),
    'node_modules/vitest': ent('vitest', '5.0.5', { dev: true }), 'node_modules/@vitest/coverage-v8': ent('@vitest/coverage-v8', '5.0.5', { dev: true }), 'node_modules/c8': ent('c8', '12.0.0', { dev: true }),
  });
  const run = async (next: string, original = OLD, extra: Partial<GuardCtx> = {}) => {
    const root = repo({ 'package-lock.json': original, 'package.json': PJ });
    return reasons([edit('package-lock.json', original, next, { needsConfirm: true })], ctx(root, { baseTree: base({ 'package-lock.json': original, 'package.json': PJ }), ...extra }));
  };
  it('a lock change explained by the added devDependencies is ok', async () => {
    expect(await run(NEW)).toBe('');
  });
  it('a change to any other entry is refused', async () => {
    const changed = JSON.parse(NEW) as { packages: Record<string, Record<string, unknown>> };
    changed.packages['node_modules/typescript'].version = '5.9.9';
    expect(await run(JSON.stringify(changed, null, 2))).toMatch(/typescript/);
  });
  it('a new entry outside the closure is refused', async () => {
    const extra = JSON.parse(NEW) as { packages: Record<string, unknown> };
    extra.packages['node_modules/left-pad'] = ent('left-pad', '1.3.0');
    expect(await run(JSON.stringify(extra, null, 2))).toMatch(/left-pad/);
  });
  it('the lock and package.json in one batch must agree on devDependencies', async () => {
    const root = repo({ 'package-lock.json': OLD, 'package.json': PJ });
    const c = ctx(root, { baseTree: base({ 'package-lock.json': OLD, 'package.json': PJ }) });
    const both = [edit('package.json', PJ, PJ_NEW, { needsConfirm: true }), edit('package-lock.json', OLD, NEW, { needsConfirm: true })];
    expect(await reasons(both, c)).toBe('');
    const onlyVitest = PJ_NEW.replace(/,\s*"c8": "12.0.0"/, '');
    expect(await reasons([edit('package.json', PJ, onlyVitest, { needsConfirm: true }), edit('package-lock.json', OLD, NEW, { needsConfirm: true })], c)).toMatch(/package\.json/);
  });
  it('a lock larger than 1 MB is read (lockfiles are big)', async () => {
    const pkgs: Record<string, object> = { 'node_modules/typescript': ent('typescript', '5.6.0', { dev: true }) };
    for (let i = 0; i < 6000; i++) pkgs[`node_modules/pkg-${i}`] = ent(`pkg-${i}`, '1.0.0', { dev: true });
    const old = lock({ typescript: '5.6.0' }, pkgs);
    expect(old.length).toBeGreaterThan(1_000_000);
    const next = lock({ typescript: '5.6.0', c8: '12.0.0' }, { ...pkgs, 'node_modules/c8': ent('c8', '12.0.0', { dev: true }) });
    expect(await run(next, old)).toBe('');
  });
});

describe('guard: service paths (S4)', () => {
  it('a service folder outside the plain set gets no created file, only a note', async () => {
    const root = repo();
    const c = ctx(root, { profile: prof(['web//api', 'ok']) });
    const r = await guardCreatedFiles([file('web/api/Dockerfile'), file('ok/Dockerfile')], c);
    expect(r.ok.map((f) => f.path)).toEqual(['ok/Dockerfile']);
    expect(r.refused.map((x) => x.path)).toEqual(['web/api/Dockerfile']);
    expect(r.refused[0]?.reason).toMatch(/service folder/);
    expect(r.notes.join(' ')).toMatch(/service folder/);
  });
  it('services whose paths are plain (including ./ and a trailing slash) pass', async () => {
    const c = ctx(repo(), { profile: prof(['./api/', '.', 'a/b-c_d.e']) });
    expect(await okPaths([file('api/Dockerfile'), file('a/b-c_d.e/Dockerfile')], c)).toEqual(['api/Dockerfile', 'a/b-c_d.e/Dockerfile']);
  });
  it('a folder with a space, a dot-dot, a dash start, an @ or a reserved name never reaches a file (note only)', async () => {
    const bad = ['my app', '../up', '-dash', 'a@b', 'aux', 'x/./y', 'sp ace/api', 'a/b+c'];
    const r = await guardCreatedFiles([], ctx(repo(), { profile: prof(bad) }));
    expect(r.notes.length).toBe(bad.length);
    for (const b of bad) expect(r.notes.join('\n')).toContain(b);
  });
  it('a created file under a bad service folder is refused whatever the normalisation (dot segments, case)', async () => {
    const c = ctx(repo(), { profile: prof(['x/./y']) });
    expect(await reasons([file('x/y/Dockerfile')], c)).toMatch(/service folder/);
  });
});

describe('guard: the result', () => {
  it('splits ok and refused per file, keeps the order, and never throws on a hostile mix', async () => {
    const root = repo({ Dockerfile: 'mine' });
    symlinkSync(root, join(root, 'loop'));
    const files = [file('a.txt'), file('Dockerfile'), file('loop/x'), file('b.txt'), file(null as unknown as string)];
    const r = await guardCreatedFiles(files, ctx(root));
    expect(r.ok.map((f) => f.path)).toEqual(['a.txt', 'b.txt']);
    expect(r.refused.length).toBe(3);
    for (const x of r.refused) expect(typeof x.reason).toBe('string');
  });
  it('every refusal reason is plain English (no stack, no raw error name)', async () => {
    const root = repo({ Dockerfile: 'mine' });
    const r = await guardCreatedFiles([file('Dockerfile'), file('..')], ctx(root));
    for (const x of r.refused) expect(x.reason).not.toMatch(/Error|ENOENT|EACCES|undefined|\[object/);
  });
  it('the files are not changed and nothing is written to the folder', async () => {
    const root = repo({ keep: 'x' });
    const f = file('new/Dockerfile');
    const before = JSON.stringify(f);
    await guardCreatedFiles([f], ctx(root));
    expect(JSON.stringify(f)).toBe(before);
    const { existsSync } = await import('node:fs');
    expect(existsSync(join(root, 'new'))).toBe(false);
  });
  it('gitBlobSha is git\'s blob sha', () => {
    expect(gitBlobSha('hello\n')).toBe('ce013625030ba8dba906f756967f9e9ca394464a');
    expect(gitBlobSha('')).toBe('e69de29bb2d1d6434b8b29ae775ad8c2e48c5391');
  });
});
