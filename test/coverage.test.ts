import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadToolSignatures, mapCoverage, type Coverage } from '../src/audit/coverage.js';
import { floorNeeds } from '../src/engine/needs.js';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import type { Capabilities, ExistingWorkflow, Layer, RepoProfile, Service } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

// A public repo whose plan allows attestations: keyless signing, so the deploy layer has sbom, signing and attestation.
const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: false,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};

const svc = (path: string, over: Partial<Service> = {}): Service => ({
  name: path === '.' ? 'app' : path.split('/').pop() as string, path, language: 'node', packageManager: 'npm', hasTests: true,
  envVars: [], dependsOn: [], scripts: ['test', 'lint'], frameworks: [], ...over,
});

/** A profile for `dir` the way readProject would build it: workflows and the hook manager read from disk. */
async function profileOf(dir: string, over: Partial<RepoProfile> = {}): Promise<RepoProfile> {
  return {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
    services: [svc('.')], terraformDirs: [], hasCompose: false,
    existingWorkflows: await readWorkflows(dir), precommit: readPrecommit(dir), ...over,
  };
}

async function coverage(dir: string, over: Partial<RepoProfile> = {}): Promise<Coverage[]> {
  const p = await profileOf(dir, over);
  return mapCoverage(p, floorNeeds(p, caps), dir);
}

function row(rows: Coverage[], layer: Layer, id: string, service?: string): Coverage {
  const found = rows.find((r) => r.need.layer === layer && r.need.id === id && (service === undefined || r.need.service === service));
  if (!found) throw new Error(`no ${id} row in ${layer}${service ? ` for ${service}` : ''}`);
  return found;
}

/** A workflow as readWorkflows would list it (the secret-names key is built, so no redact rule matches this file). */
const listedWorkflow = (path: string) => ({ path, triggers: ['push'], deploys: false, ['secrets' + 'Used']: [], jobs: ['scan'] }) as unknown as ExistingWorkflow;
const wf = (dir: string, name: string, body: string) => writeIn(dir, `.github/workflows/${name}`, body);
const job = (steps: string, extra = '') => `jobs:\n  scan:\n    runs-on: ubuntu-latest\n${extra}    steps:\n${steps}`;
const run = (cmd: string) => `      - run: ${cmd}\n`;

describe('mapCoverage (brief)', () => {
  it('coverage: no workflows → all gaps', async () => {
    const dir = makeTempDir();
    const rows = await coverage(dir);
    const p = await profileOf(dir);
    expect(rows).toHaveLength(floorNeeds(p, caps).length);
    for (const r of rows) {
      expect(r.status, `${r.need.layer} ${r.need.id}`).toBe('missing');
      expect(r.by).toBeUndefined();
      expect(r.where).toBeUndefined();
      expect(r.why).toMatch(/^[A-Z].*\.$/);
    }
    expect(new Set(rows.map((r) => r.need.layer))).toEqual(new Set(['pre-commit', 'push', 'merge']));
    expect(row(rows, 'pre-commit', 'secrets').why).toBe('Without a secret scan before commit, a leaked key is in git history forever.');
  });

  it('coverage: gitleaks on push only → secrets push covered, merge partial', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: push\n${job(run('gitleaks detect --redact'))}`);
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'secrets')).toMatchObject({ status: 'covered', by: 'gitleaks', where: '.github/workflows/ci.yml (job scan)' });
    const merge = row(rows, 'merge', 'secrets');
    expect(merge).toMatchObject({ status: 'partial', by: 'gitleaks' });
    expect(merge.why).toMatch(/not on every pull request/);
    expect(row(rows, 'pre-commit', 'secrets').status).toBe('missing'); // CI is not a pre-commit hook
    expect(row(rows, 'push', 'sast', 'app').status).toBe('missing');
  });

  it('coverage: continue-on-error semgrep → partial', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job('      - uses: semgrep/semgrep-action@v1\n        continue-on-error: true\n')}`);
    const rows = await coverage(dir);
    for (const layer of ['push', 'merge'] as const) {
      const r = row(rows, layer, 'sast', 'app');
      expect(r).toMatchObject({ status: 'partial', by: 'semgrep' });
      expect(r.why).toMatch(/continue-on-error/);
    }
    // job-level continue-on-error, and an expression (it may be true), count the same
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `on: [push, pull_request]\n${job(run('semgrep scan'), '    continue-on-error: true\n')}`);
    expect(row(await coverage(dir2), 'push', 'sast', 'app').status).toBe('partial');
    const dir3 = makeTempDir();
    wf(dir3, 'ci.yml', `on: [push, pull_request]\n${job('      - run: semgrep scan\n        continue-on-error: \${{ matrix.experimental }}\n')}`);
    expect(row(await coverage(dir3), 'push', 'sast', 'app').status).toBe('partial');
    // continue-on-error: false is blocking
    const dir4 = makeTempDir();
    wf(dir4, 'ci.yml', `on: [push, pull_request]\n${job('      - run: semgrep scan\n        continue-on-error: false\n')}`);
    expect(row(await coverage(dir4), 'push', 'sast', 'app').status).toBe('covered');
  });

  it('coverage: local reusable workflow followed one level', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', 'on: pull_request\njobs:\n  security:\n    uses: ./.github/workflows/security.yml\n');
    wf(dir, 'security.yml', `on: workflow_call\njobs:\n  leaks:\n    runs-on: x\n    steps:\n${run('gitleaks detect')}  deeper:\n    uses: ./.github/workflows/deeper.yml\n`);
    wf(dir, 'deeper.yml', `on: workflow_call\n${job(run('semgrep scan'))}`);
    const rows = await coverage(dir);
    expect(row(rows, 'merge', 'secrets')).toMatchObject({
      status: 'covered', by: 'gitleaks', where: '.github/workflows/ci.yml (job security) → .github/workflows/security.yml (job leaks)',
    });
    // the call inside the called workflow is a second level: not followed, so unknown (not covered, not missing)
    const sast = row(rows, 'merge', 'sast', 'app');
    expect(sast.status).toBe('unknown');
    expect(sast.why).toMatch(/one level/);
    // the called workflow's own trigger (workflow_call) never counts by itself: deeper.yml alone covers nothing
    expect(row(rows, 'push', 'sast', 'app').status).not.toBe('covered');
  });

  it('coverage: remote reusable workflow → unknown, not missing', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', 'on: [push, pull_request]\njobs:\n  sec:\n    uses: other-org/shared/.github/workflows/security.yml@v2\n');
    const rows = await coverage(dir);
    for (const layer of ['push', 'merge'] as const) {
      const r = row(rows, layer, 'secrets');
      expect(r).toMatchObject({ status: 'unknown', by: 'other-org/shared/.github/workflows/security.yml@v2', where: '.github/workflows/ci.yml (job sec)' });
      expect(r.why).toMatch(/can't see inside/);
    }
    expect(row(rows, 'merge', 'gate').status).toBe('missing'); // pipegen's own check, never inside someone else's workflow
    expect(row(rows, 'pre-commit', 'secrets').status).toBe('missing'); // hooks are read, not guessed
  });

  it('coverage: husky hook running gitleaks → pre-commit covered', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.husky/pre-commit', '#!/bin/sh\n# gitleaks used to run here: nogitleaksx\ngitleaks protect --staged --redact\nnpx lint-staged\n');
    const rows = await coverage(dir);
    expect(row(rows, 'pre-commit', 'secrets')).toMatchObject({ status: 'covered', by: 'gitleaks', where: '.husky/pre-commit' });
    expect(row(rows, 'pre-commit', 'secrets').why).toMatch(/husky pre-commit hook/);
    expect(row(rows, 'pre-commit', 'hooks')).toMatchObject({ status: 'covered', by: 'husky' });
    expect(row(rows, 'pre-commit', 'format-lint', 'app')).toMatchObject({ status: 'covered', by: 'lint-staged' });
    expect(row(rows, 'push', 'secrets').status).toBe('missing'); // a hook is not CI
  });
});

describe('mapCoverage (rulings)', () => {
  it('coverage: pre-commit framework and lefthook hook configs are read (S4)', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', 'repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.0.0\n    hooks:\n      - id: gitleaks\n  - repo: local\n    hooks:\n      - id: fmt\n        entry: ruff format\n        stages: [manual]\n');
    const rows = await coverage(dir);
    expect(row(rows, 'pre-commit', 'secrets')).toMatchObject({ status: 'covered', by: 'gitleaks', where: '.pre-commit-config.yaml' });
    expect(row(rows, 'pre-commit', 'hooks')).toMatchObject({ status: 'covered', by: 'pre-commit' });
    expect(row(rows, 'pre-commit', 'format-lint', 'app').status).toBe('missing'); // manual stage only: not a pre-commit hook
    const dir2 = makeTempDir();
    writeIn(dir2, 'lefthook.yml', 'pre-commit:\n  commands:\n    leaks:\n      run: trufflehog git file://. --since-commit HEAD\n');
    expect(row(await coverage(dir2), 'pre-commit', 'secrets')).toMatchObject({ status: 'covered', by: 'trufflehog', where: 'lefthook.yml' });
  });

  it('coverage: S4 hooks, hooks-ci, gate and deploy-verify rows', async () => {
    const dir = makeTempDir();
    wf(dir, 'hooks.yml', `on: [push, pull_request]\n${job(run('pre-commit run --all-files'))}`);
    const rows = await coverage(dir, { precommit: 'pre-commit', services: [svc('.', { scripts: ['start'] })] });
    expect(row(rows, 'pre-commit', 'hooks')).toMatchObject({ status: 'covered', by: 'pre-commit' });
    expect(row(rows, 'push', 'hooks-ci')).toMatchObject({ status: 'covered', by: 'pre-commit' });
    expect(row(rows, 'merge', 'hooks-ci').status).toBe('covered');
    expect(row(rows, 'merge', 'gate')).toMatchObject({ status: 'missing' });
    expect(row(rows, 'merge', 'gate').why).toBe('No single required check sums up every scan, so a pull request with a failing scan can still be merged.');
    expect(row(rows, 'deploy', 'deploy-verify', 'app').status).toBe('missing');
    expect(row(rows, 'deploy', 'deploy-verify', 'app').why).toBe("Deploys don't check that the commit passed the pipeline, so an unchecked commit can be deployed.");
    // husky hooks run in CI count too
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `on: push\n${job(run('sh ./.husky/pre-commit'))}`);
    expect(row(await coverage(dir2), 'push', 'hooks-ci')).toMatchObject({ status: 'covered', by: 'husky-hooks' });
  });

  it('coverage: S4 deploy layer: SBOM on release covered, on pull requests only partial', async () => {
    const runnable = { services: [svc('.', { scripts: ['start'] })] };
    const dir = makeTempDir();
    wf(dir, 'release.yml', `on:\n  release:\n    types: [published]\n${job('      - uses: anchore/sbom-action@v0\n      - uses: actions/attest-build-provenance@v2\n')}`);
    const rows = await coverage(dir, runnable);
    expect(row(rows, 'deploy', 'sbom', 'app')).toMatchObject({ status: 'covered', by: 'syft' });
    expect(row(rows, 'deploy', 'attestation', 'app')).toMatchObject({ status: 'covered', by: 'attest-build-provenance' });
    expect(row(rows, 'deploy', 'signing', 'app').status).toBe('missing');
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `on: pull_request\n${job(run('syft . -o spdx-json') + run('cosign sign --yes img'))}`);
    const rows2 = await coverage(dir2, runnable);
    expect(row(rows2, 'deploy', 'sbom', 'app').status).toBe('partial');
    expect(row(rows2, 'deploy', 'signing', 'app')).toMatchObject({ status: 'partial', by: 'cosign' });
    // push to the default branch counts as the deploy trigger
    const dir3 = makeTempDir();
    wf(dir3, 'main.yml', `on:\n  push:\n    branches: [main]\n${job(run('syft . -o spdx-json'))}`);
    expect(row(await coverage(dir3, runnable), 'deploy', 'sbom', 'app').status).toBe('covered');
  });

  it("coverage: S5 the service's own npm test / lint / pytest scripts count", async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npm ci') + run('npm   test') + run('pnpm run lint'))}`);
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm test`' });
    expect(row(rows, 'merge', 'full-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm test`' });
    expect(row(rows, 'push', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'your own `pnpm run lint`' });
    expect(row(rows, 'push', 'unit-tests', 'app').why).toBe('Your own `npm test` runs on every push.');
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `on: push\n${job(run('python -m pytest -q'))}`);
    expect(row(await coverage(dir2), 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `python -m pytest`' });
    // whole words only: not a substring, not inside another word, not in a shell comment
    const dir3 = makeTempDir();
    wf(dir3, 'ci.yml', `on: push\n${job(run('nogitleaksx --npm-testx') + run('cat .gitleaks.toml') + run('"# gitleaks later"'))}`);
    const rows3 = await coverage(dir3);
    expect(row(rows3, 'push', 'secrets').status).toBe('missing');
    expect(row(rows3, 'push', 'unit-tests', 'app').status).toBe('missing');
  });

  it('coverage: S6 trigger forms (string, list, map) and branch filters', async () => {
    const status = async (on: string, layer: Layer) => {
      const dir = makeTempDir();
      wf(dir, 'ci.yml', `${on}\n${job(run('gitleaks detect'))}`);
      return row(await coverage(dir), layer, 'secrets').status;
    };
    expect(await status('on: pull_request', 'merge')).toBe('covered');
    expect(await status('on: pull_request', 'push')).toBe('partial');
    expect(await status('on: [push]', 'push')).toBe('covered');
    expect(await status('on:\n  push:\n  pull_request:\n    branches: [main]', 'merge')).toBe('covered');
    expect(await status('on:\n  pull_request:\n    branches: [release]', 'merge')).toBe('partial'); // never on PRs to main
    expect(await status("on:\n  push:\n    branches: ['**']", 'push')).toBe('covered');
    expect(await status('on:\n  push:\n    branches: [main]', 'push')).toBe('partial'); // feature branches excluded
    expect(await status('on:\n  push:\n    branches-ignore: [main]', 'push')).toBe('covered');
    expect(await status("on:\n  push:\n    branches: ['**', '!feature/**']", 'push')).toBe('partial');
    expect(await status("on:\n  push:\n    tags: ['v*']", 'push')).toBe('partial'); // tags only: no branch push
    expect(await status('on: pull_request_target', 'merge')).toBe('partial');
    expect(await status('on: workflow_dispatch', 'push')).toBe('partial');
    expect(await status("on:\n  schedule:\n    - cron: '0 3 * * *'", 'merge')).toBe('partial');
    expect(await status('on: workflow_call', 'push')).toBe('missing'); // runs only when called
    // a YAML 1.1 writer may have turned the `on` key into true; readWorkflows reads both spellings, and so does this
    expect(await status('true: [push, pull_request]', 'merge')).toBe('covered');
  });

  it('coverage: S26 working-directory and cd scope a job to one service; a repo-wide job covers all', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]
jobs:
  api:
    runs-on: x
    defaults:
      run:
        working-directory: apps/api
    steps:
      - run: npm test
  web:
    runs-on: x
    steps:
      - run: cd apps/web && npx eslint .
      - run: |
          cd apps/web
          npx vitest run
      - run: semgrep scan
`);
    const services = [svc('apps/api'), svc('apps/web')];
    const rows = await coverage(dir, { services, monorepo: 'npm-workspaces' });
    expect(row(rows, 'push', 'unit-tests', 'api')).toMatchObject({ status: 'covered', by: 'your own `npm test`', where: '.github/workflows/ci.yml (job api)' });
    expect(row(rows, 'push', 'unit-tests', 'web')).toMatchObject({ status: 'covered', by: 'vitest' });
    expect(row(rows, 'push', 'lint', 'web')).toMatchObject({ status: 'covered', by: 'eslint' });
    expect(row(rows, 'push', 'lint', 'api').status).toBe('missing');
    for (const s of ['api', 'web']) expect(row(rows, 'push', 'sast', s).status).toBe('covered');
    // a step working-directory works the same way
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `on: push\n${job('      - run: npm test\n        working-directory: ./apps/web/\n')}`);
    const rows2 = await coverage(dir2, { services, monorepo: 'npm-workspaces' });
    expect(row(rows2, 'push', 'unit-tests', 'web').status).toBe('covered');
    expect(row(rows2, 'push', 'unit-tests', 'api').status).toBe('missing');
  });

  it('coverage: S3 local composite action followed one level; a same-owner remote action is unknown', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job('      - uses: actions/checkout@v4\n      - uses: O/internal-ci/lint@v1\n      - uses: ./.github/actions/scan\n')}`);
    writeIn(dir, '.github/actions/scan/action.yml', "name: scan\nruns:\n  using: composite\n  steps:\n    - run: gitleaks detect\n      shell: bash\n    - uses: ./.github/actions/deeper\n");
    writeIn(dir, '.github/actions/deeper/action.yaml', "runs:\n  using: composite\n  steps:\n    - run: semgrep scan\n      shell: bash\n");
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'secrets')).toMatchObject({ status: 'covered', by: 'gitleaks', where: '.github/workflows/ci.yml (job scan) → .github/actions/scan/action.yml' });
    const sast = row(rows, 'push', 'sast', 'app');
    expect(sast.status).toBe('unknown'); // the second level, or the owner's own action: pipegen can't see inside
    const deps = row(rows, 'push', 'deps', 'app');
    expect(deps).toMatchObject({ status: 'unknown', by: 'O/internal-ci/lint@v1' });
    expect(deps.why).toMatch(/owner's own account/);
  });

  it('coverage: S2 symlinked .github/workflows, .husky and local action dir are not read', async () => {
    const outside = makeTempDir();
    writeIn(outside, 'workflows/ci.yml', `on: push\n${job(run('gitleaks detect'))}`);
    writeIn(outside, 'husky/pre-commit', 'gitleaks protect --staged\n');
    writeIn(outside, 'action/action.yml', "runs:\n  using: composite\n  steps:\n    - run: gitleaks detect\n      shell: bash\n");
    const dir = makeTempDir();
    mkdirSync(join(dir, '.github'));
    symlinkSync(join(outside, 'workflows'), join(dir, '.github/workflows'));
    symlinkSync(join(outside, 'husky'), join(dir, '.husky'));
    const listed = listedWorkflow('.github/workflows/ci.yml');
    const rows = await coverage(dir, { existingWorkflows: [listed], precommit: 'husky' });
    expect(row(rows, 'push', 'secrets').status).toBe('missing');
    expect(row(rows, 'pre-commit', 'secrets').status).not.toBe('covered');
    // a local action reached through a symbolic link
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `on: push\n${job('      - uses: ./tools/scan\n')}`);
    mkdirSync(join(dir2, 'tools'));
    symlinkSync(join(outside, 'action'), join(dir2, 'tools/scan'));
    const r2 = row(await coverage(dir2), 'push', 'secrets');
    expect(r2.status).toBe('unknown');
    expect(r2.why).toMatch(/couldn't read/);
  });

  it('coverage: S2 a local call outside the repo (./../x) is refused', async () => {
    const base = makeTempDir();
    const dir = join(base, 'repo');
    writeIn(base, 'x/action.yml', "runs:\n  using: composite\n  steps:\n    - run: gitleaks detect\n      shell: bash\n");
    writeIn(base, 'repo/.github/workflows/ci.yml', `on: push\n${job('      - uses: ./../x\n')}`);
    wf(dir, 'reuse.yml', 'on: push\njobs:\n  up:\n    uses: ./../../x/action.yml\n');
    const rows = await coverage(dir);
    const r = row(rows, 'push', 'secrets');
    expect(r.status).toBe('unknown');
    expect(r.why).toMatch(/outside the repo/);
  });

  it('coverage: S2 a workflow path with control characters is skipped; where is validated and capped', async () => {
    const dir = makeTempDir();
    const bad = '.github/workflows/a‮b.yml';
    writeIn(dir, bad, `on: push\n${job(run('gitleaks detect'))}`);
    const listed = listedWorkflow(bad);
    expect(row(await coverage(dir, { existingWorkflows: [listed] }), 'push', 'secrets').status).toBe('missing');
    // a very long job id: where is capped; a job id that fails the pattern is shown by number
    const dir2 = makeTempDir();
    const long = `j${'x'.repeat(1000)}`; // YAML keys stay under 1024 characters
    wf(dir2, 'ci.yml', `on: push\njobs:\n  ${long}:\n    runs-on: x\n    steps:\n${run('gitleaks detect')}  "bad job‮":\n    runs-on: x\n    steps:\n${run('semgrep scan')}`);
    const rows = await coverage(dir2);
    const where = row(rows, 'push', 'secrets').where ?? '';
    expect(Array.from(where).length).toBeLessThanOrEqual(300);
    expect(where.startsWith('.github/workflows/ci.yml (job j')).toBe(true);
    expect(row(rows, 'push', 'sast', 'app').where).toBe('.github/workflows/ci.yml (job #2)');
  });
});

describe('loadToolSignatures (S1)', () => {
  it('signatures: the bundled list loads and every entry names actions or commands', () => {
    const list = loadToolSignatures();
    const ids = list.map((t) => t.id);
    for (const id of ['gitleaks', 'trufflehog', 'semgrep', 'codeql', 'snyk', 'trivy', 'grype', 'osv-scanner', 'npm-audit', 'zap', 'eslint', 'jest', 'vitest', 'cosign', 'syft', 'attest-build-provenance']) {
      expect(ids).toContain(id);
    }
    expect(new Set(ids).size).toBe(ids.length);
    for (const t of list) expect((t.actions?.length ?? 0) + (t.commands?.length ?? 0)).toBeGreaterThan(0);
  });

  it('signatures: unknown keys, unknown categories and bad patterns are refused', () => {
    const dir = makeTempDir();
    const load = (yaml: string) => {
      writeIn(dir, 'sig.yml', yaml);
      return () => loadToolSignatures(join(dir, 'sig.yml'));
    };
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n')()).toHaveLength(1);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n    extra: 1\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [nope]\n    commands: [a]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    actions: [noslash]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: ["a(b|c)*"]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n  - id: a\n    categories: [sast]\n    commands: [b]\n')).toThrow(/not valid/);
  });
});
