// Plan E E3 (Task 2, second half; ruling S17, E2 r1-m3): the hardened compat copies of the user's build/test workflows. A
// compat copy runs in the scratch repo next to the user's real test keys, so a job that needs a secret, an environment, a
// write or id-token permission, a runner that isn't GitHub-hosted, or a dropped job is NOT COMPARED (listed with the reason),
// never run with more rights. Copies are re-rendered from the parsed model and must parse back exactly. No network.
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { parseYaml } from '../src/engine/yaml-parse.js';
import { COMPAT_PREFIX, compatCopies, compatCopiesFrom, type CompatResult } from '../src/proof/harness.js';
import { checkCentralPins } from '../src/proof/snapshot.js';
import { proofTarget } from '../src/proof/target.js';
import { gitRepoWith } from './helpers/git-repo-with.js';
import { profile } from './helpers/render.js';

type Wf = { name: string; on: unknown; permissions: Record<string, string>; env?: Record<string, string>; jobs: Record<string, Record<string, unknown>> };
const wf = (content: string, path = '.github/workflows/ci.yml'): CompatResult => compatCopiesFrom([{ path, content }]);
const copyOf = (r: CompatResult, path = `${COMPAT_PREFIX}ci.yml`): Wf => parse(r.files.find((f) => f.path === path)!.content) as Wf;
const why = (r: CompatResult, job: string): string | undefined => r.notCompared.find((n) => n.job === job)?.why;
// secret names built at run time (test/no-secret-literals.test.ts)
// the id-token key built at run time too (a redact pattern reads that key with a value as a credential)
const IDT = ['id', 'tok' + 'en'].join('-');
const PW = ['pass', 'word'].join('');
const SEC = ['secr', 'ets'].join('');
const S = (name: string) => ['${{ ', 'secrets', '.', name, ' }}'].join('');

const CI = `
name: CI
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'
permissions:
  contents: read
env:
  NODE_ENV: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run build
  test:
    needs: build
    runs-on: ubuntu-22.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - run: npm test
        env:
          GH: ${S('GITHUB_TOKEN')}
  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - run: npx vercel deploy --prod
`;

describe('compat copies', () => {
  it('compat: copies keep build/test jobs, drop deploy jobs, only pull_request', () => {
    const r = wf(CI);
    expect(r.files.map((f) => f.path)).toEqual([`${COMPAT_PREFIX}ci.yml`]);
    const c = copyOf(r);
    expect(c.on).toBe('pull_request');
    expect(Object.keys(c.jobs)).toEqual(['build', 'test']);
    expect(c.jobs.test!.needs).toBe('build');
    expect(c.jobs.test!['timeout-minutes']).toBe(10);
    expect(c.env).toEqual({ NODE_ENV: 'test' });
    expect(why(r, 'deploy')).toMatch(/deploys/);
    expect(r.files[0]!.content).not.toMatch(/workflow_dispatch|schedule|push:|pull_request_target|workflow_run/);
    // a job named deploy/release/publish, and a whole release workflow, are dropped too
    const named = wf(`on: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n  unit:\n    runs-on: ubuntu-latest\n    steps: [{ run: make test }]\n`);
    expect(Object.keys(copyOf(named).jobs)).toEqual(['unit']);
    expect(why(named, 'release')).toMatch(/deploys/);
    const rel = wf('on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n', '.github/workflows/release.yml');
    expect(rel.files).toEqual([]);
    expect(rel.notCompared).toEqual([{ workflow: '.github/workflows/release.yml', job: '*', why: expect.stringMatching(/deploys/) }]);
    // a workflow that never runs on push or pull_request isn't a build/test workflow
    const call = wf('on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n');
    expect(call.files).toEqual([]);
    expect(call.notCompared[0]!.why).toMatch(/does not run on pushes or pull requests/);
    // every kept file is one pipegen wrote whole (E2 takes it), with no user text beyond the model
    expect(Object.keys(r.files[0]!).sort()).toEqual(['content', 'part', 'path', 'reason', 'repo']);
  });

  it('compat: permissions contents: read; id-token and environment removed', () => {
    const r = wf(`on: [push, pull_request]
permissions: read-all
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    concurrency: lint-\${{ github.ref }}
    steps: [{ run: npm run lint }]
  oidc:
    runs-on: ubuntu-latest
    permissions:
      ${IDT}: write
      contents: read
    steps: [{ run: make }]
  env:
    runs-on: ubuntu-latest
    environment: staging
    steps: [{ run: make }]
  writes:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps: [{ run: make }]
  all:
    runs-on: ubuntu-latest
    permissions: write-all
    steps: [{ run: make }]
`);
    const c = copyOf(r);
    expect(c.permissions).toEqual({ contents: 'read' });
    expect(Object.keys(c.jobs)).toEqual(['lint']);
    expect(c.jobs.lint!.permissions).toEqual({ contents: 'read' });
    expect(c.jobs.lint!.concurrency).toBeUndefined();
    expect(r.files[0]!.content).not.toMatch(/id-token|environment|write/);
    expect(why(r, 'oidc')).toMatch(/id-token/);
    expect(why(r, 'env')).toMatch(/uses an environment/);
    // the id-token permission at read (not a value GitHub takes) is still never copied
    const idRead = wf(`on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      ${IDT}: read\n    steps: [{ run: make }]\n`);
    expect(why(idRead, 'a')).toMatch(/id-token/);
    expect(why(r, 'writes')).toMatch(/contents: write/);
    expect(why(r, 'all')).toMatch(/write-all/);
    // a workflow-level write permission reaches every job that has none of its own
    const top = wf('on: pull_request\npermissions:\n  packages: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n');
    expect(top.files).toEqual([]);
    expect(why(top, 'a')).toMatch(/packages: write/);
  });

  it('compat: job using secrets or a self-hosted runner → not compared', () => {
    const r = wf(`on: pull_request
jobs:
  ok:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
        env: { T: "${S('GITHUB_TOKEN')}" }
  keyed:
    runs-on: ubuntu-latest
    steps:
      - run: make
        env: { K: "${S('STRIPE_KEY')}" }
  upper:
    runs-on: ubuntu-latest
    steps:
      - run: make
        env: { K: "\${{ SECRETS.STRIPE_KEY }}" }
  bracket:
    runs-on: ubuntu-latest
    steps: [{ run: "echo \${{ secrets['NPM'] }}" }]
  json:
    runs-on: ubuntu-latest
    steps: [{ run: "echo \${{ toJSON(secrets) }}" }]
  cond:
    runs-on: ubuntu-latest
    if: secrets.DEPLOY_TOKEN != ''
    steps: [{ run: make }]
  stepcond:
    runs-on: ubuntu-latest
    steps: [{ run: make, if: "secrets.X" }]
  quoted:
    runs-on: ubuntu-latest
    steps: [{ run: "echo \${{ format('}}', secrets.X) }}" }]
  container:
    runs-on: ubuntu-latest
    container:
      image: node:20
      credentials: { username: u, ${PW}: "${S('REG')}" }
    steps: [{ run: make }]
  self:
    runs-on: self-hosted
    steps: [{ run: make }]
  labels:
    runs-on: [self-hosted, ubuntu-latest]
    steps: [{ run: make }]
  group:
    runs-on: { group: big }
    steps: [{ run: make }]
  inherit:
    uses: ./.github/workflows/reusable.yml
    ${SEC}: inherit
`);
    expect(Object.keys(copyOf(r).jobs)).toEqual(['ok']);
    for (const j of ['keyed', 'upper', 'bracket', 'json', 'cond', 'stepcond', 'quoted', 'container']) expect(why(r, j), j).toMatch(/secret other than GITHUB_TOKEN/);
    for (const j of ['self', 'labels', 'group']) expect(why(r, j), j).toMatch(/GitHub-hosted/);
    expect(why(r, 'inherit')).toMatch(/reusable workflow/);
    expect(r.files[0]!.content).not.toMatch(/STRIPE|NPM|REG|DEPLOY|self-hosted/);
    // a secret in the workflow-level env: no job is compared
    const top = wf(`on: pull_request\nenv:\n  K: ${S('API_KEY')}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n`);
    expect(top.files).toEqual([]);
    expect(top.notCompared[0]).toMatchObject({ job: '*', why: expect.stringMatching(/secret/) });
  });

  it('compat: job that needs a dropped job → not compared', () => {
    const r = wf(`on: pull_request
jobs:
  setup:
    runs-on: ubuntu-latest
    steps: [{ run: make, env: { K: "${S('KEY')}" } }]
  build:
    needs: setup
    runs-on: ubuntu-latest
    steps: [{ run: make }]
  test:
    needs: [build]
    runs-on: ubuntu-latest
    steps: [{ run: make test }]
  lint:
    runs-on: ubuntu-latest
    steps: [{ run: make lint }]
`);
    expect(Object.keys(copyOf(r).jobs)).toEqual(['lint']);
    expect(why(r, 'setup')).toMatch(/secret/);
    expect(why(r, 'build')).toMatch(/needs the job setup/);
    expect(why(r, 'test')).toMatch(/needs the job build/);
    // in any order of the file: a needs chain written backwards is followed to the end
    const back = wf(`on: pull_request
jobs:
  c:
    needs: b
    runs-on: ubuntu-latest
    steps: [{ run: make }]
  b:
    needs: a
    runs-on: ubuntu-latest
    steps: [{ run: make }]
  a:
    runs-on: ubuntu-latest
    steps: [{ run: make, env: { K: "${S('KEY')}" } }]
  d:
    runs-on: ubuntu-latest
    steps: [{ run: make }]
`);
    expect(Object.keys(copyOf(back).jobs)).toEqual(['d']);
    expect(why(back, 'c')).toMatch(/needs the job b/);
  });

  it('compat: matrix or expression runs-on → not compared', () => {
    const r = wf(`on: pull_request
jobs:
  matrix:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: \${{ matrix.os }}
    steps: [{ run: make }]
  expr:
    runs-on: \${{ vars.RUNNER }}
    steps: [{ run: make }]
  node:
    strategy:
      matrix:
        node: [20, 22]
    runs-on: ubuntu-latest
    steps: [{ run: "echo \${{ matrix.node }}" }]
`);
    expect(why(r, 'matrix')).toMatch(/expression or a matrix value/);
    expect(why(r, 'expr')).toMatch(/expression or a matrix value/);
    // a matrix of values on a literal hosted runner is kept exactly
    expect(copyOf(r).jobs.node!.strategy).toEqual({ matrix: { node: [20, 22] } });
  });

  it('compat (E2 r1-m3): re-rendered from the model: no merge key, tag or anchor, parses back exactly', () => {
    const r = wf(`on: pull_request
x-common: &steps
  - run: npm ci
jobs:
  a:
    runs-on: ubuntu-latest
    env: &env { A: "yes", B: "on", C: "0755", D: "2026-01-01", E: "null", F: "1e3", G: "  lead", H: "multi\\nline" }
    steps: *steps
`);
    // an unknown top-level key: the whole workflow is not modelled
    expect(r.files).toEqual([]);
    expect(r.notCompared[0]!.why).toMatch(/x-common/);
    const ok = wf(`on: pull_request
jobs:
  a:
    runs-on: ubuntu-latest
    env: &env { A: "yes", B: "on", C: "0755", D: "2026-01-01", E: "null", F: "1e3", G: "  lead", H: "multi\\nline", I: 3.10, J: true }
    steps: &s
      - run: |
          npm ci
          npm test
  b:
    runs-on: ubuntu-latest
    env: *env
    steps: *s
`);
    const text = ok.files[0]!.content;
    expect(text).not.toMatch(/(?:^|\s)[&*][A-Za-z]|<<|!!|^%/m);
    const strict = parseYaml(text, 'strict');
    expect('problems' in strict).toBe(false);
    const c = copyOf(ok);
    expect(c.jobs.a!.env).toEqual({ A: 'yes', B: 'on', C: '0755', D: '2026-01-01', E: 'null', F: '1e3', G: '  lead', H: 'multi\nline', I: 3.1, J: true });
    expect(c.jobs.b!.env).toEqual(c.jobs.a!.env);
    expect(c.jobs.a!.steps).toEqual([{ run: 'npm ci\nnpm test\n' }]);
    // a YAML 1.1 reader sees the same strings: every string is quoted (or a block literal)
    expect(text).toContain('A: "yes"');
    expect(text).toContain('C: "0755"');
    // merge keys and tags in the source can't be modelled exactly: not compared, with a note, never a stop
    for (const bad of ['on: pull_request\njobs:\n  a:\n    <<: { runs-on: ubuntu-latest }\n    steps: [{ run: make }]\n', 'on: pull_request\njobs:\n  a:\n    runs-on: !!str ubuntu-latest\n    steps: [{ run: make }]\n', 'on: pull_request\non: push\njobs: {}\n']) {
      const b = wf(bad);
      expect(b.files, bad).toEqual([]);
      expect(b.notCompared[0]!.why, bad).toMatch(/can't model it exactly/);
    }
    // E2's pin check reads every compat copy without stopping
    const t = proofTarget({ owner: 'CrisWorking', repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main' });
    expect(() => checkCentralPins(ok.files.map((f) => ({ path: f.path, content: f.content })), t, undefined, undefined)).not.toThrow();
  });

  it('compat: a pipelines reference, an unknown key, pipegen\'s own files and odd names are not compared', () => {
    const r = compatCopiesFrom([
      { path: '.github/workflows/ci.yml', content: 'on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ uses: CrisWorking/pipelines/x@v1 }]\n  b:\n    runs-on: ubuntu-latest\n    snapshot: img\n    steps: [{ run: make }]\n  c:\n    runs-on: ubuntu-latest\n    steps: [{ run: make, odd: 1 }]\n' },
      { path: '.github/workflows/pipegen.yml', content: 'on: push\njobs: {}\n' },
      { path: '.github/workflows/pipegen-compat-x.yml', content: 'on: push\njobs: {}\n' },
      { path: '.github/workflows/sub/ci.yml', content: 'on: push\njobs: {}\n' },
      { path: '.github/workflows/my ci.yml', content: 'on: push\njobs: {}\n' },
    ]);
    expect(r.files).toEqual([]);
    const by = (w: string, j: string) => r.notCompared.find((n) => n.workflow === w && n.job === j)?.why;
    expect(by('.github/workflows/ci.yml', 'a')).toMatch(/pipelines/);
    expect(by('.github/workflows/ci.yml', 'b')).toMatch(/snapshot/);
    expect(by('.github/workflows/ci.yml', 'c')).toMatch(/odd/);
    // a job with no steps is not compared (the proof's own check would otherwise stop on it)
    expect(why(wf('on: pull_request\njobs:\n  e:\n    runs-on: ubuntu-latest\n    steps: []\n'), 'e')).toMatch(/no steps/);
    expect(by('.github/workflows/pipegen.yml', '*')).toMatch(/pipegen's own/);
    expect(by('.github/workflows/pipegen-compat-x.yml', '*')).toMatch(/pipegen's own/);
    expect(by('.github/workflows/sub/ci.yml', '*')).toMatch(/not a top-level/);
    expect(by('.github/workflows/my ci.yml', '*')).toMatch(/not plain/);
  });

  it('compat (E3-R2): a job using actions/cache is not compared; the user\'s tag-pinned actions are kept', () => {
    const r = wf(`on: pull_request
jobs:
  cached:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with: { path: ~/.npm, key: k }
      - run: make
  restore:
    runs-on: ubuntu-latest
    steps: [{ uses: actions/cache/restore@v4, with: { path: x, key: k } }, { run: make }]
  plain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { cache: npm }
      - run: make
`);
    expect(Object.keys(copyOf(r).jobs)).toEqual(['plain']);
    expect(why(r, 'cached')).toMatch(/actions\/cache/);
    expect(why(r, 'restore')).toMatch(/actions\/cache/);
    expect(copyOf(r).jobs.plain!.steps).toEqual([{ uses: 'actions/checkout@v4' }, { uses: 'actions/setup-node@v4', with: { cache: 'npm' } }, { run: 'make' }]);
  });

  it('compat (M3): an alias inside one job value is copied without an anchor and the job is kept', () => {
    const r = wf(`on: pull_request
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: x
        env: &e { A: "1", B: "2" }
      - run: y
        env: *e
`);
    expect(r.notCompared).toEqual([]);
    const text = r.files[0]!.content;
    expect(text).not.toMatch(/(?:^|\s)[&*][A-Za-z]/m);
    expect(copyOf(r).jobs.a!.steps).toEqual([{ run: 'x', env: { A: '1', B: '2' } }, { run: 'y', env: { A: '1', B: '2' } }]);
  });

  it('compat: copies are read from HEAD, never the working tree', async () => {
    const dir = gitRepoWith({ '.github/workflows/ci.yml': 'on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n' });
    const { writeFileSync } = await import('node:fs');
    writeFileSync(`${dir}/.github/workflows/ci.yml`, 'on: pull_request\njobs:\n  dirty:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n');
    const r = await compatCopies(profile(), dir);
    expect(Object.keys(copyOf(r).jobs)).toEqual(['a']);
  });
});
