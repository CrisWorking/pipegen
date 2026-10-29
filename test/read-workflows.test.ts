import { symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import { readProject } from '../src/read/project.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const wf = (dir: string, name: string, body: string) => writeIn(dir, `.github/workflows/${name}`, body);
const one = async (body: string, name = 'ci.yml') => {
  const dir = makeTempDir();
  wf(dir, name, body);
  return (await readWorkflows(dir))[0];
};

describe('readWorkflows', () => {
  it('workflows: triggers, jobs and secrets parsed', async () => {
    const w = await one(`name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
        env:
          NPM_PUBLISH: \${{ secrets.NPM_TOKEN }}
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets['SLACK_HOOK'] }} \${{ secrets["NPM_TOKEN"] }}
`);
    expect(w).toEqual({ path: '.github/workflows/ci.yml', triggers: ['push', 'pull_request'], deploys: false, ['secrets' + 'Used']: ['NPM_TOKEN', 'SLACK_HOOK'], jobs: ['build', 'lint'] });
  });

  it('workflows: tagPinned counts the uses: lines pinned by a tag or branch (Task 9, PS36); a commit, a local path and an image are not counted', async () => {
    const w = await one(`on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@${'a'.repeat(40)}
      - uses: ./.github/actions/local
      - uses: docker://alpine:3
      - uses: owner/repo/sub@main
  b:
    uses: org/shared/.github/workflows/x.yml@v2
`);
    expect(w?.tagPinned).toBe(3);
    // a workflow with none leaves the field out
    expect((await one('on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n', 'b.yml'))?.tagPinned).toBeUndefined();
  });

  it('workflows: usesUnchecked marks a workflow with a uses: line pipegen could not check; an uppercase commit counts as pinned (review I2, M1)', async () => {
    const long = `o/r@v${'1'.repeat(5000)}`;
    const w = await one(`on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: ${long}\n      - uses: actions/checkout@${'A'.repeat(40)}\n`);
    expect(w?.usesUnchecked).toBe(true);
    expect(w?.tagPinned).toBeUndefined();
    expect((await one('on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n', 'c.yml'))?.usesUnchecked).toBeUndefined();
  });

  it('workflows: environment key marks deploy', async () => {
    const w = await one('name: CI\non: push\njobs:\n  ship:\n    runs-on: x\n    environment: production\n    steps:\n      - run: echo hi\n');
    expect(w?.deploys).toBe(true);
  });

  it("workflows: 'vercel deploy' in run marks deploy", async () => {
    const w = await one('name: CI\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: |\n          npm ci\n          npx vercel --prod\n');
    expect(w?.deploys).toBe(true);
    const u = await one('name: CI\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: superfly/flyctl-actions@v1\n');
    expect(u?.deploys).toBe(true);
  });

  it('workflows: name or file name containing release marks deploy', async () => {
    expect((await one('name: Release\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n'))?.deploys).toBe(true);
    expect((await one('name: CI\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n', 'publish.yaml'))?.deploys).toBe(true);
  });

  it('workflows: plain test workflow not deploy', async () => {
    const w = await one('name: CI\non: [push, pull_request]\njobs:\n  test:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n');
    expect(w?.deploys).toBe(false);
    expect(w?.triggers).toEqual(['push', 'pull_request']);
  });

  it('workflows: on as string, list and map', async () => {
    expect((await one('on: push\njobs: {}\n'))?.triggers).toEqual(['push']);
    expect((await one('on: [push, pull_request, push]\njobs: {}\n'))?.triggers).toEqual(['push', 'pull_request']);
    expect((await one('on:\n  schedule:\n    - cron: "0 0 * * *"\n  workflow_dispatch:\njobs: {}\n'))?.triggers).toEqual(['schedule', 'workflow_dispatch']);
  });

  it('workflows: secrets names only, values never read', async () => {
    const w = await one(`on: push
jobs:
  a:
    runs-on: x
    steps:
      - run: echo
        env:
          A: \${{ secrets.GOOD_ONE }}
          B: \${{ secrets.bad-name }}
          C: super-secret-value-12345
secrets_note${':'} hunter2
`);
    expect(w?.secretsUsed).toEqual(['GOOD_ONE']);
    expect(JSON.stringify(w)).not.toMatch(/hunter2|super-secret/);
  });

  it('workflows: hostile workflow (alias bomb, over-4KB run line) does not crash', async () => {
    const dir = makeTempDir();
    const aliases = Array.from({ length: 60 }, (_, i) => `  - *a`).join('\n');
    wf(dir, 'bomb.yml', `a: &a [1, 2]\nb:\n${aliases}\n`);
    wf(dir, 'long.yml', `on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: "${'x'.repeat(10000)} vercel \${{ secrets.LONG_ONE }}"\n`);
    wf(dir, 'ok.yml', 'on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm test\n');
    wf(dir, 'broken.yml', 'on: [unclosed\n');
    const notes: string[] = [];
    const out = await readWorkflows(dir, undefined, notes);
    const byPath = Object.fromEntries(out.map((w) => [w.path, w]));
    expect(byPath['.github/workflows/ok.yml']?.jobs).toEqual(['t']);
    expect(byPath['.github/workflows/long.yml']?.deploys).toBe(false);
    expect(byPath['.github/workflows/long.yml']?.secretsUsed).toEqual([]);
    expect(byPath['.github/workflows/bomb.yml']).toBeUndefined();
    expect(byPath['.github/workflows/broken.yml']).toBeUndefined();
    expect(notes.length).toBeGreaterThanOrEqual(2);
  });

  it('workflows: deploy words inside other words do not count (butterfly, overwhelm)', async () => {
    const body = (run: string) => `name: CI\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ${run}\n`;
    expect((await one(body('echo butterfly')))?.deploys).toBe(false);
    expect((await one(body('echo overwhelm')))?.deploys).toBe(false);
  });

  it('workflows: deployment script and npm_deploy still count as deploy', async () => {
    const body = (run: string) => `name: CI\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ${run}\n`;
    for (const run of ['./deployment.sh', 'npm run npm_deploy', 'flyctl deploy', 'helm upgrade x']) {
      expect((await one(body(run)))?.deploys, run).toBe(true);
    }
  });

  it('workflows: symlinked .github/workflows directory not read', async () => {
    const dir = makeTempDir();
    const other = makeTempDir();
    writeIn(other, 'a.yml', 'on: push\njobs: {}\n');
    writeIn(dir, '.github/keep', '1');
    symlinkSync(other, join(dir, '.github/workflows'));
    expect(await readWorkflows(dir)).toEqual([]);
  });

  it('workflows: a file whose name has control characters is skipped with a note; other paths are stored raw', async () => {
    const dir = makeTempDir();
    wf(dir, 'a\u001b[31mb.yml', 'on: push\njobs: {}\n');
    wf(dir, 'c\u202ed.yml', 'on: push\njobs: {}\n');
    wf(dir, 'ok name.yml', 'on: push\njobs: {}\n');
    const notes: string[] = [];
    const out = await readWorkflows(dir, undefined, notes);
    expect(out.map((w) => w.path)).toEqual(['.github/workflows/ok name.yml']);
    expect(notes).toEqual([
      'Skipped .github/workflows/ab.yml: its file name has control or invisible characters, or is too long.',
      'Skipped .github/workflows/cd.yml: its file name has control or invisible characters, or is too long.',
    ]);
    for (const n of notes) expect(n).not.toMatch(/[\u001b\u202e]/);
  });

  it('workflows: a file name with a zero-width space or a tag character is skipped with the same note', async () => {
    const dir = makeTempDir();
    wf(dir, 'a\u200bb.yml', 'on: push\njobs: {}\n');
    wf(dir, 'c\u{e0041}d.yml', 'on: push\njobs: {}\n');
    wf(dir, 'ok.yml', 'on: push\njobs: {}\n');
    const notes: string[] = [];
    const out = await readWorkflows(dir, undefined, notes);
    expect(out.map((w) => w.path)).toEqual(['.github/workflows/ok.yml']);
    expect(notes).toEqual([
      'Skipped .github/workflows/ab.yml: its file name has control or invisible characters, or is too long.',
      'Skipped .github/workflows/cd.yml: its file name has control or invisible characters, or is too long.',
    ]);
  });

  it('workflows: skip notes use the shared plain-English reasons and are never repeated', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.github/workflows/bin.yml', 'on: push\u0000\n');
    writeIn(dir, '.github/workflows/big.yml', '#'.repeat(1_000_001));
    wf(dir, 'broken.yml', 'on: [unclosed\n');
    const notes: string[] = [];
    await readWorkflows(dir, undefined, notes);
    await readWorkflows(dir, undefined, notes);
    expect(notes).toEqual([
      'Skipped .github/workflows/big.yml: it is larger than 1 MB.',
      'Skipped .github/workflows/bin.yml: it is a binary file.',
      'Skipped .github/workflows/broken.yml: it could not be parsed.',
    ]);
    const linked = makeTempDir();
    symlinkSync(makeTempDir(), join(linked, '.github'));
    const linkNotes: string[] = [];
    expect(await readWorkflows(linked, undefined, linkNotes)).toEqual([]);
    expect(await readWorkflows(linked, undefined, linkNotes)).toEqual([]);
    expect(linkNotes).toEqual(['Skipped .github/workflows: it is reached through a symbolic link.']);
  });

  it('workflows: job ids that GitHub would not accept are dropped', async () => {
    const w = await one('on: push\njobs:\n  build:\n    runs-on: x\n  ok-job_2:\n    runs-on: x\n  _private:\n    runs-on: x\n  "bad id":\n    runs-on: x\n  "1st":\n    runs-on: x\n  "x\\e[31m":\n    runs-on: x\n  "a.b":\n    runs-on: x\n');
    expect(w?.jobs).toEqual(['build', 'ok-job_2', '_private']);
  });

  it('workflows: trigger names other than lowercase words are dropped', async () => {
    expect((await one('on: [push, "pu\\x01sh", Push, "pull-request", workflow_dispatch]\njobs: {}\n'))?.triggers).toEqual(['push', 'workflow_dispatch']);
    expect((await one('on:\n  "pu\\x01sh":\n  pull_request:\njobs: {}\n'))?.triggers).toEqual(['pull_request']);
    expect((await one('on: "pu\\x01sh"\njobs: {}\n'))?.triggers).toEqual([]);
  });

  it('workflows: ignores non-yaml files, subfolders and symlinks', async () => {
    const dir = makeTempDir();
    wf(dir, 'a.yml', 'on: push\njobs: {}\n');
    wf(dir, 'notes.md', 'x');
    wf(dir, 'sub/b.yml', 'on: push\njobs: {}\n');
    writeIn(dir, 'real.yml', 'on: push\njobs: {}\n');
    symlinkSync(join(dir, 'real.yml'), join(dir, '.github/workflows/link.yml'));
    expect((await readWorkflows(dir)).map((w) => w.path)).toEqual(['.github/workflows/a.yml']);
  });

  it('workflows: caps at 200 files with a note', async () => {
    const dir = makeTempDir();
    for (let i = 0; i < 205; i++) wf(dir, `w${String(i).padStart(3, '0')}.yml`, 'on: push\njobs: {}\n');
    const notes: string[] = [];
    expect(await readWorkflows(dir, undefined, notes)).toHaveLength(200);
    expect(notes.join(' ')).toMatch(/200/);
  });

  it('workflows: wired into readProject', async () => {
    const dir = makeRepo('node-npm', 'https://github.com/o/r.git');
    wf(dir, 'ci.yml', 'on: push\njobs:\n  t:\n    runs-on: x\n');
    mkdirHusky(dir);
    const p = await readProject(dir);
    expect(p.existingWorkflows.map((w) => w.path)).toEqual(['.github/workflows/ci.yml']);
    expect(p.precommit).toBe('husky');
  });
});

const mkdirHusky = (dir: string) => writeIn(dir, '.husky/pre-commit', 'npm test\n');

describe('readPrecommit', () => {
  it('precommit: husky folder detected', () => {
    const dir = makeTempDir();
    mkdirHusky(dir);
    expect(readPrecommit(dir)).toBe('husky');
  });

  it('precommit: pre-commit and lefthook detected, priority pre-commit > husky > lefthook, none is null', () => {
    const dir = makeTempDir();
    expect(readPrecommit(dir)).toBeNull();
    writeIn(dir, 'lefthook.yml', 'x: 1');
    expect(readPrecommit(dir)).toBe('lefthook');
    mkdirHusky(dir);
    expect(readPrecommit(dir)).toBe('husky');
    writeIn(dir, '.pre-commit-config.yaml', 'repos: []');
    expect(readPrecommit(dir)).toBe('pre-commit');
    const d2 = makeTempDir();
    writeIn(d2, 'lefthook.yaml', 'x: 1');
    expect(readPrecommit(d2)).toBe('lefthook');
  });

  it('precommit: every config name lefthook 2.2.2 reads counts as lefthook (and its -local files)', () => {
    const names = ['lefthook.yml', 'lefthook.yaml', 'lefthook.toml', 'lefthook.json', 'lefthook.jsonc', '.lefthook.yml', '.lefthook.yaml', '.lefthook.toml', '.lefthook.json', '.lefthook.jsonc',
      '.config/lefthook.yml', '.config/lefthook.yaml', '.config/lefthook.toml', '.config/lefthook.json', '.config/lefthook.jsonc',
      'lefthook-local.yml', 'lefthook-local.toml', '.lefthook-local.yml', '.lefthook-local.json', '.config/lefthook-local.yml'];
    for (const n of names) {
      const d = makeTempDir();
      writeIn(d, n, 'x: 1');
      expect(readPrecommit(d), n).toBe('lefthook');
    }
  });

  it('precommit: symlinked config ignored', () => {
    const dir = makeTempDir();
    const other = makeTempDir();
    writeIn(other, 'f.yaml', 'repos: []');
    writeIn(other, 'husky/x', '1');
    symlinkSync(join(other, 'f.yaml'), join(dir, '.pre-commit-config.yaml'));
    symlinkSync(join(other, 'husky'), join(dir, '.husky'));
    symlinkSync(join(other, 'f.yaml'), join(dir, 'lefthook.yml'));
    expect(readPrecommit(dir)).toBeNull();
  });
});
