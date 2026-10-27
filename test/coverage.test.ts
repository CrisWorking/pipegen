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
    wf(dir2, 'ci.yml', `on: [push, pull_request]\n${job(run('semgrep scan --error'), '    continue-on-error: true\n')}`);
    expect(row(await coverage(dir2), 'push', 'sast', 'app').status).toBe('partial');
    const dir3 = makeTempDir();
    wf(dir3, 'ci.yml', `on: [push, pull_request]\n${job('      - run: semgrep scan --error\n        continue-on-error: \${{ matrix.experimental }}\n')}`);
    expect(row(await coverage(dir3), 'push', 'sast', 'app').status).toBe('partial');
    // continue-on-error: false is blocking, but only when the run itself fails on findings: semgrep scan needs --error
    const dir4 = makeTempDir();
    wf(dir4, 'ci.yml', `on: [push, pull_request]\n${job('      - run: semgrep scan --error\n        continue-on-error: false\n')}`);
    expect(row(await coverage(dir4), 'push', 'sast', 'app').status).toBe('covered');
    const dir5 = makeTempDir();
    wf(dir5, 'ci.yml', `on: [push, pull_request]\n${job('      - run: semgrep scan\n        continue-on-error: false\n')}`);
    const r5 = row(await coverage(dir5), 'push', 'sast', 'app');
    expect(r5).toMatchObject({ status: 'partial', by: 'semgrep-scan' });
    expect(r5.why).toBe("The semgrep-scan check runs, but doesn't fail on findings unless told to, so it can't block anything.");
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
    expect(row(rows, 'pre-commit', 'format-lint', 'app').status).toBe('partial'); // manual stage only: set up, but not run before a commit (fix round 1, I2)
    const dir2 = makeTempDir();
    writeIn(dir2, 'lefthook.yml', 'pre-commit:\n  commands:\n    leaks:\n      run: trufflehog git file://. --since-commit HEAD --fail\n');
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
      - run: semgrep ci
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
    expect(row(rows, 'push', 'secrets')).toMatchObject({ status: 'unknown', why: "Some workflow files couldn't be read, so pipegen can't tell." });
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
    const bad = '.github/workflows/a\u202eb.yml';
    writeIn(dir, bad, `on: push\n${job(run('gitleaks detect'))}`);
    const listed = listedWorkflow(bad);
    expect(row(await coverage(dir, { existingWorkflows: [listed] }), 'push', 'secrets').status).toBe('unknown'); // never a silent skip
    // a very long job id: where is capped; a job id that fails the pattern is shown by number
    const dir2 = makeTempDir();
    const long = `j${'x'.repeat(1000)}`; // YAML keys stay under 1024 characters
    wf(dir2, 'ci.yml', `on: push\njobs:\n  ${long}:\n    runs-on: x\n    steps:\n${run('gitleaks detect')}  "bad job\u202e":\n    runs-on: x\n    steps:\n${run('semgrep scan')}`);
    const rows = await coverage(dir2);
    const where = row(rows, 'push', 'secrets').where ?? '';
    expect(Array.from(where).length).toBeLessThanOrEqual(300);
    expect(where.startsWith('.github/workflows/ci.yml (job j')).toBe(true);
    expect(row(rows, 'push', 'sast', 'app').where).toBe('.github/workflows/ci.yml (job #2)');
  });
});

/** The status (and row) of one need for a single workflow body, with optional profile overrides. */
async function one(body: string, layer: Layer, id: string, over: Partial<RepoProfile> = {}, service?: string): Promise<Coverage> {
  const dir = makeTempDir();
  wf(dir, 'ci.yml', body);
  return row(await coverage(dir, over), layer, id, service);
}
const both = 'on: [push, pull_request]\n';
const runnable = { services: [svc('.', { scripts: ['start'] })] };

describe('mapCoverage (fix round 1)', () => {
  it('coverage: I1 shell suppression (|| true, || :, || exit 0, set +e) → partial', async () => {
    for (const cmd of ['gitleaks detect || true', 'gitleaks detect || :', 'gitleaks detect || exit 0', 'gitleaks detect && echo ok || true']) {
      const r = await one(`${both}${job(run(JSON.stringify(cmd)))}`, 'push', 'secrets'); // quoted: a bare `|| :` would be a YAML key
      expect(r.status, cmd).toBe('partial');
      expect(r.why).toBe("The gitleaks check runs, but its exit code is ignored (by ||, a pipe, an if, set +e, the background & or the step's shell), so it can't block anything.");
    }
    // with errexit off, a tool that isn't the step's last command can't fail the step (the last one still can)
    expect((await one(`${both}${job('      - run: |\n          set +e\n          gitleaks detect\n          echo done\n')}`, 'push', 'secrets')).status).toBe('partial');
    // set -e turns errexit back on; a later || true in another list doesn't reach the tool
    expect((await one(`${both}${job('      - run: |\n          set +e\n          set -eo pipefail\n          gitleaks detect\n')}`, 'push', 'secrets')).status).toBe('covered');
    expect((await one(`${both}${job(run('gitleaks detect; echo done || true'))}`, 'push', 'secrets')).status).toBe('covered');
    // a hook that swallows the exit code is partial too; a non-blocking need (format-lint) only needs the tool to run
    const dir = makeTempDir();
    writeIn(dir, '.husky/pre-commit', 'gitleaks protect --staged || true\nnpx lint-staged || true\n');
    const rows = await coverage(dir);
    expect(row(rows, 'pre-commit', 'secrets').status).toBe('partial');
    expect(row(rows, 'pre-commit', 'format-lint', 'app').status).toBe('covered');
  });

  it('coverage: I1 soft-fail flags and tools that fail only with a flag', async () => {
    const st = async (cmd: string, id = 'secrets', over: Partial<RepoProfile> = {}) =>
      (await one(`${both}${job(run(cmd))}`, id === 'iac' ? 'merge' : 'push', id, over, id === 'secrets' || id === 'iac' ? undefined : 'app')).status;
    expect(await st('gitleaks detect --exit-code 0')).toBe('partial');
    expect(await st('gitleaks detect --exit-code=0')).toBe('partial');
    expect(await st('gitleaks detect --exit-code 1')).toBe('covered');
    expect(await st('trufflehog git file://.')).toBe('partial'); // the CLI fails only with --fail
    expect(await st('trufflehog git file://. --fail')).toBe('covered');
    expect(await st('trivy fs .', 'deps')).toBe('partial'); // trivy exits 0 on findings unless --exit-code
    expect(await st('trivy fs --exit-code 1 .', 'deps')).toBe('covered');
    expect(await st('trivy fs --exit-code 0 .', 'deps')).toBe('partial');
    expect(await st('grype dir:.', 'deps')).toBe('partial');
    expect(await st('grype dir:. --fail-on high', 'deps')).toBe('covered');
    expect(await st('semgrep ci', 'sast')).toBe('covered');
    expect(await st('semgrep --config auto --error', 'sast')).toBe('covered');
    expect(await st('semgrep --config auto', 'sast')).toBe('partial');
    expect(await st('detect-secrets-hook --baseline .secrets.baseline')).toBe('covered');
    expect(await st('detect-secrets scan > .secrets.baseline')).toBe('partial');
    expect(await st('checkov -d . --soft-fail', 'iac', { terraformDirs: ['infra'] })).toBe('partial');
    expect(await st('checkov -d .', 'iac', { terraformDirs: ['infra'] })).toBe('covered');
    // flags on continuation lines belong to the same command
    expect((await one(`${both}${job('      - run: |\n          trivy fs . \\\n            --exit-code 1\n')}`, 'push', 'deps', {}, 'app')).status).toBe('covered');
    const r = await one(`${both}${job(run('gitleaks detect --exit-code 0'))}`, 'push', 'secrets');
    expect(r.why).toBe("The gitleaks check runs, but is set not to fail on findings, so it can't block anything.");
  });

  it('coverage: I1 action inputs: exit-code, fail-build, fail_action, soft_fail, warn-only', async () => {
    const st = async (uses: string, withLines: string, id: string, over: Partial<RepoProfile> = {}, service?: string) =>
      (await one(`${both}${job(`      - uses: ${uses}\n${withLines === '' ? '' : `        with:\n${withLines}`}`)}`, id === 'iac' ? 'merge' : 'push', id, over, service)).status;
    expect(await st('aquasecurity/trivy-action@0.28.0', '', 'deps', {}, 'app')).toBe('partial');
    expect(await st('aquasecurity/trivy-action@0.28.0', "          exit-code: '1'\n", 'deps', {}, 'app')).toBe('covered');
    expect(await st('aquasecurity/trivy-action@0.28.0', "          exit-code: '0'\n", 'deps', {}, 'app')).toBe('partial');
    expect(await st('aquasecurity/trivy-action@0.28.0', '          exit-code: ${{ inputs.code }}\n', 'deps', {}, 'app')).toBe('partial');
    expect(await st('anchore/scan-action@v6', '', 'deps', {}, 'app')).toBe('covered');
    expect(await st('anchore/scan-action@v6', '          fail-build: false\n', 'deps', {}, 'app')).toBe('partial');
    expect(await st('trufflesecurity/trufflehog@v3', '', 'secrets')).toBe('covered'); // the action always passes --fail
    expect(await st('bridgecrewio/checkov-action@v12', '          soft_fail: true\n', 'iac', { terraformDirs: ['infra'] })).toBe('partial');
    expect(await st('actions/dependency-review-action@v4', '          warn-only: true\n', 'deps', {}, 'app')).toBe('partial');
    expect(await st('actions/dependency-review-action@v4', '', 'deps', {}, 'app')).toBe('covered');
    const dast = async (withLines: string) => (await one(`${both}${job(`      - uses: zaproxy/action-baseline@v0.14.0\n${withLines}`)}`, 'merge', 'dast', runnable, 'app')).status;
    expect(await dast('')).toBe('partial'); // fail_action defaults to false
    expect(await dast("        with:\n          fail_action: true\n")).toBe('covered');
  });

  it('coverage: U5 CodeQL analyze is partial with its own why', async () => {
    const r = await one(`${both}${job('      - uses: github/codeql-action/init@v3\n      - uses: github/codeql-action/analyze@v3\n')}`, 'merge', 'sast', {}, 'app');
    expect(r).toMatchObject({ status: 'partial', by: 'codeql' });
    expect(r.why).toBe('CodeQL reports findings but does not fail the job; they block only if code scanning merge protection is on.');
    // upload-sarif alone is not CodeQL
    expect((await one(`${both}${job('      - uses: github/codeql-action/upload-sarif@v3\n')}`, 'merge', 'sast', {}, 'app')).status).toBe('missing');
  });

  it('coverage: I2 a paths or paths-ignore filter is the wrong trigger', async () => {
    const on = "on:\n  push:\n    paths: ['src/**']\n  pull_request:\n    paths-ignore: ['docs/**']\n";
    const push = await one(`${on}${job(run('gitleaks detect'))}`, 'push', 'secrets');
    expect(push.status).toBe('partial');
    expect(push.why).toBe('The gitleaks check runs, but not on every push.');
    expect((await one(`${on}${job(run('gitleaks detect'))}`, 'merge', 'secrets')).status).toBe('partial');
    expect((await one(`on:\n  push:\n    branches: [main]\n    paths: ['src/**']\n${job(run('syft .'))}`, 'deploy', 'sbom', runnable, 'app')).status).toBe('partial');
  });

  it('coverage: I3 job and step if: conditions', async () => {
    const st = async (cond: string, layer: Layer, where: 'job' | 'step' = 'job') => {
      const body = where === 'job'
        ? `${both}jobs:\n  scan:\n    runs-on: x\n    if: ${cond}\n    steps:\n${run('gitleaks detect')}`
        : `${both}${job(`      - run: gitleaks detect\n        if: ${cond}\n`)}`;
      return one(body, layer, 'secrets');
    };
    const merge = await st("github.event_name == 'push'", 'merge');
    expect(merge.status).toBe('partial');
    expect(merge.why).toBe('The gitleaks check runs only when a condition holds, so it may not run on every pull request.');
    expect((await st("github.ref == 'refs/heads/main'", 'push')).status).toBe('partial');
    expect((await st("${{ github.ref == 'refs/heads/main' }}", 'push', 'step')).status).toBe('partial');
    expect((await st('false', 'push')).status).toBe('missing'); // a disabled job runs nothing
    expect((await st('${{ false }}', 'push', 'step')).status).toBe('missing');
    expect((await st('always()', 'push')).status).toBe('covered');
    expect((await st('${{ !cancelled() }}', 'push', 'step')).status).toBe('covered');
    expect((await st("github.repository == 'o/r'", 'push')).status).toBe('covered'); // a fork guard
    expect((await st("success() && (github.repository_owner == 'o')", 'push')).status).toBe('covered');
    expect((await st('failure()', 'push')).status).toBe('partial'); // runs only after something failed
    // a calling job's if: applies to the called workflow
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  sec:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/sec.yml\n`);
    wf(dir, 'sec.yml', `on: workflow_call\n${job(run('gitleaks detect'))}`);
    expect(row(await coverage(dir), 'merge', 'secrets').status).toBe('partial');
  });

  it('coverage: I4 exact action paths; setup-only actions and npm audit signatures never count', async () => {
    const st = async (steps: string, layer: Layer, id: string, over: Partial<RepoProfile> = {}) => (await one(`${both}${job(steps)}`, layer, id, over, 'app')).status;
    expect(await st('      - uses: snyk/actions/setup@master\n', 'push', 'deps')).toBe('missing');
    expect(await st('      - uses: snyk/actions/node@master\n', 'push', 'deps')).toBe('covered');
    expect(await st('      - uses: snyk/actions/python-3.10@master\n', 'push', 'deps')).toBe('covered');
    expect(await st('      - uses: anchore/sbom-action/download-syft@v0\n', 'deploy', 'sbom', runnable)).toBe('missing');
    expect(await st('      - uses: biomejs/setup-biome@v2\n', 'push', 'lint')).toBe('missing');
    expect(await st(run('npm audit signatures'), 'push', 'deps')).toBe('missing');
    expect(await st(run('npm audit --audit-level=high'), 'push', 'deps')).toBe('covered');
  });

  it('coverage: I5 uses: steps run from the root even when the job has a run default', async () => {
    const services = [svc('apps/api'), svc('apps/web')];
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  sast:\n    runs-on: x\n    defaults:\n      run:\n        working-directory: apps/api\n    steps:\n      - uses: github/codeql-action/analyze@v3\n      - uses: ./.github/actions/scan\n`);
    writeIn(dir, '.github/actions/scan/action.yml', 'runs:\n  using: composite\n  steps:\n    - run: gitleaks detect\n      shell: bash\n    - run: osv-scanner -r .\n      shell: bash\n');
    const rows = await coverage(dir, { services, monorepo: 'npm-workspaces' });
    for (const s of ['api', 'web']) {
      expect(row(rows, 'push', 'sast', s).status).toBe('partial'); // reached every service (CodeQL is partial, U5)
      expect(row(rows, 'push', 'deps', s).status).toBe('covered'); // a composite action's run steps start at the root
    }
  });

  it('coverage: M1 workflows readWorkflows skipped make would-be-missing rows unknown', async () => {
    const dir = makeTempDir();
    const p = await profileOf(dir);
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir, { skippedWorkflows: 1 });
    const r = row(rows, 'push', 'secrets');
    expect(r).toMatchObject({ status: 'unknown', why: "Some workflow files couldn't be read, so pipegen can't tell." });
    expect(row(rows, 'pre-commit', 'secrets').status).toBe('missing'); // hooks are read directly
    expect(row(rows, 'merge', 'gate').status).toBe('missing');
  });

  it('coverage: M2 a tool counts only where a command starts', async () => {
    const st = async (cmd: string, id = 'secrets') => (await one(`${both}${job(run(cmd))}`, 'push', id, {}, id === 'secrets' ? undefined : 'app')).status;
    expect(await st('pip install semgrep', 'sast')).toBe('missing');
    expect(await st('echo "TODO gitleaks"')).toBe('missing');
    expect(await st('some-tool --format semgrep', 'sast')).toBe('missing');
    expect(await st('curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8/gitleaks.tgz | tar xz')).toBe('missing');
    expect(await st('./bin/gitleaks detect')).toBe('covered');
    expect(await st('env CI=1 GITLEAKS_CONFIG=x gitleaks detect')).toBe('covered');
    expect(await st('sudo -E gitleaks detect')).toBe('covered');
    expect(await st('time gitleaks detect')).toBe('covered');
    expect(await st('npx --yes eslint .', 'lint')).toBe('covered');
    expect(await st('pnpm dlx eslint .', 'lint')).toBe('covered');
    expect(await st('uv run pytest', 'unit-tests')).toBe('covered');
    expect(await st('pipx run pip-audit', 'deps')).toBe('covered');
    expect(await st('python -m semgrep ci', 'sast')).toBe('covered');
    expect(await st('echo start && gitleaks detect')).toBe('covered');
    expect(await st('result=$(gitleaks detect)')).toBe('covered');
    expect(await st('docker run --rm -v "$GITHUB_WORKSPACE:/repo" zricethezav/gitleaks:v8.18.0 detect --source /repo')).toBe('covered');
    expect(await st('docker run --rm -v "$GITHUB_WORKSPACE:/src" aquasec/trivy:0.50.0 fs /src', 'deps')).toBe('partial'); // no --exit-code
  });

  it('coverage: M5 docker:// steps, unknown cd targets, symlinked .github, types and branch filter edge cases', async () => {
    const r = await one(`${both}${job('      - uses: docker://zricethezav/gitleaks:v8.18.0\n        with:\n          args: detect --exit-code 0\n')}`, 'push', 'secrets');
    expect(r).toMatchObject({ status: 'partial', by: 'gitleaks' });
    expect((await one(`${both}${job('      - uses: docker://ghcr.io/gitleaks/gitleaks:latest\n')}`, 'push', 'secrets')).status).toBe('covered');
    // cd to a directory that can't be known: repo-wide needs still count, per-service needs don't
    expect((await one(`${both}${job(run('cd "$APP_DIR" && gitleaks detect'))}`, 'push', 'secrets')).status).toBe('covered');
    expect((await one(`${both}${job(run('cd "$APP_DIR" && npm test'))}`, 'push', 'unit-tests', {}, 'app')).status).toBe('missing');
    // types without synchronize: not every pull request update
    expect((await one(`on:\n  pull_request:\n    types: [opened]\n${job(run('gitleaks detect'))}`, 'merge', 'secrets')).status).toBe('partial');
    // branches and branches-ignore together are invalid: never the right trigger
    expect((await one(`on:\n  push:\n    branches: ['**']\n    branches-ignore: [main]\n${job(run('gitleaks detect'))}`, 'push', 'secrets')).status).toBe('partial');
    // glob features: [class], ? (zero or one of the previous character), + (one or more), \ escapes
    const push = async (patterns: string) => (await one(`on:\n  push:\n    branches: [${patterns}, 'feature/**']\n${job(run('gitleaks detect'))}`, 'push', 'secrets')).status;
    expect(await push("'[p]ipegen-feature'")).toBe('covered');
    expect(await push("'[q-z]ipegen-feature'")).toBe('partial');
    expect(await push("'pipegen-featurex?'")).toBe('covered');
    expect(await push("'pipegen-featur+e'")).toBe('covered');
    expect(await push("'pipegen-featurx+e'")).toBe('partial');
    expect(await push("'pipegen\\-feature'")).toBe('covered');
    // a symlinked whole .github: nothing behind it is read
    const outside = makeTempDir();
    writeIn(outside, 'workflows/ci.yml', `on: push\n${job(run('gitleaks detect'))}`);
    const dir = makeTempDir();
    symlinkSync(outside, join(dir, '.github'));
    const rows = await coverage(dir, { existingWorkflows: [listedWorkflow('.github/workflows/ci.yml')] });
    expect(row(rows, 'push', 'secrets').status).toBe('unknown');
  });

  it('coverage: M5 a workflow over the job cap gives unknown, never missing', async () => {
    const jobs = Array.from({ length: 101 }, (_, i) => `  j${i}:\n    runs-on: x\n    steps:\n${run('echo hi')}`).join('');
    const r = await one(`${both}jobs:\n${jobs}`, 'push', 'secrets');
    expect(r).toMatchObject({ status: 'unknown', why: "The workflows are too large to read in full, so pipegen can't tell." });
  });

  it('coverage: M5 hostile 4 KB lines across a 1 MB workflow finish quickly (linear scan)', async () => {
    const kinds = ['cd a && ', 'npm ', '|| ', 'docker run -v x ', 'sudo env A=1 ', '$(', 'trivy ', '"\'', 'set +e; '];
    const lines = kinds.map((k) => k.repeat(Math.floor(3900 / k.length)));
    const body = Array.from({ length: 240 }, (_, i) => `          ${lines[i % lines.length]}`).join('\n');
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  j:\n    runs-on: x\n    if: ${'('.repeat(3000)}always()${')'.repeat(3000)}\n    steps:\n      - run: |\n${body}\n`);
    const p = await profileOf(dir);
    expect(p.existingWorkflows).toHaveLength(1); // under the 1 MB read limit, so it really is scanned
    const t = performance.now();
    await mapCoverage(p, floorNeeds(p, caps), dir);
    expect(performance.now() - t).toBeLessThan(5000);
  });
});

describe('mapCoverage (fix round 2)', () => {
  // Every probe from the round-1 re-review (adv.test.ts, adv2.test.ts), with the status each must have now.
  const runnableTf = { services: [svc('.', { scripts: ['start'] })], terraformDirs: ['infra'] };
  const cases: [string, string, Layer, string, Coverage['status']][] = [
    ['|| on the next line (no backslash)', `${both}${job('      - run: |\n          gitleaks detect ||\n            true\n')}`, 'push', 'secrets', 'partial'],
    ['|| echo', `${both}${job('      - run: gitleaks detect || echo "leaks found"\n')}`, 'push', 'secrets', 'partial'],
    ['{ …; } || true', `${both}${job('      - run: "{ gitleaks detect; } || true"\n')}`, 'push', 'secrets', 'partial'],
    ['( a; b ) || true', `${both}${job('      - run: "(gitleaks detect; echo x) || true"\n')}`, 'push', 'secrets', 'partial'],
    ['multi-line group || true', `${both}${job('      - run: |\n          {\n            gitleaks detect\n            echo scanned\n          } || true\n')}`, 'push', 'secrets', 'partial'],
    ['pipe to tee (default shell: no pipefail)', `${both}${job('      - run: gitleaks detect | tee out.txt\n')}`, 'push', 'secrets', 'partial'],
    ['if ! tool; then', `${both}${job('      - run: |\n          if ! gitleaks detect; then echo found; fi\n')}`, 'push', 'secrets', 'partial'],
    ['set -x +e, tool not last', `${both}${job('      - run: |\n          set -x +e\n          gitleaks detect\n          echo done\n')}`, 'push', 'secrets', 'partial'],
    ['command -v probe', `${both}${job('      - run: command -v gitleaks || go install github.com/zricethezav/gitleaks/v8@latest\n')}`, 'push', 'secrets', 'missing'],
    ['quoted ; in echo', `${both}${job('      - run: echo "todo; gitleaks detect"\n')}`, 'push', 'secrets', 'missing'],
    ['sudo -u <tool-named user>', `${both}${job('      - run: sudo -u gitleaks id\n')}`, 'push', 'secrets', 'missing'],
    ['env -u <tool name>', `${both}${job('      - run: env -u gitleaks printenv\n')}`, 'push', 'secrets', 'missing'],
    ['custom shell bash {0} (no -e), tool not last', `${both}${job('      - shell: bash {0}\n        run: |\n          gitleaks detect\n          echo done\n')}`, 'push', 'secrets', 'partial'],
    ['if: cancelled()', `${both}jobs:\n  scan:\n    runs-on: x\n    if: cancelled()\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'partial'],
    ['if: !success()', `${both}jobs:\n  scan:\n    runs-on: x\n    if: \${{ !success() }}\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'partial'],
    ['if: !always()', `${both}jobs:\n  scan:\n    runs-on: x\n    if: "!always()"\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'missing'],
    ['if: always() && event_name', `${both}jobs:\n  scan:\n    runs-on: x\n    if: always() && github.event_name == 'push'\n    steps:\n      - run: gitleaks detect\n`, 'merge', 'secrets', 'partial'],
    ['if: guard for another repo', `${both}jobs:\n  scan:\n    runs-on: x\n    if: github.repository == 'someone-else/other'\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'missing'],
    ['if: false && always()', `${both}jobs:\n  scan:\n    runs-on: x\n    if: \${{ false && always() }}\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'missing'],
    ['if: 1 == 2', `${both}jobs:\n  scan:\n    runs-on: x\n    if: 1 == 2\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'partial'],
    ['continue-on-error ${{ true }}', `${both}${job('      - run: gitleaks detect\n        continue-on-error: \${{ true }}\n')}`, 'push', 'secrets', 'partial'],
    ['job continue-on-error "true"', `${both}${job('      - run: gitleaks detect\n', "    continue-on-error: 'true'\n")}`, 'push', 'secrets', 'partial'],
    ['Fail-Build: false (input names ignore case)', `${both}${job('      - uses: anchore/scan-action@v6\n        with:\n          Fail-Build: false\n')}`, 'push', 'deps', 'partial'],
    ['fail-build: "no"', `${both}${job("      - uses: anchore/scan-action@v6\n        with:\n          fail-build: 'no'\n")}`, 'push', 'deps', 'partial'],
    ['fail-build: "TRUE"', `${both}${job("      - uses: anchore/scan-action@v6\n        with:\n          fail-build: 'TRUE'\n")}`, 'push', 'deps', 'covered'],
    ['Soft_Fail: true checkov-action', `${both}${job('      - uses: bridgecrewio/checkov-action@v12\n        with:\n          Soft_Fail: true\n')}`, 'merge', 'iac', 'partial'],
    ['soft_fail: "yes" checkov-action (only "true" counts upstream)', `${both}${job("      - uses: bridgecrewio/checkov-action@v12\n        with:\n          soft_fail: 'yes'\n")}`, 'merge', 'iac', 'covered'],
    ['soft_fail: false tfsec-action (any value counts upstream)', `${both}${job('      - uses: aquasecurity/tfsec-action@v1\n        with:\n          soft_fail: false\n')}`, 'merge', 'iac', 'partial'],
    ['Warn-Only: true dependency-review', `${both}${job('      - uses: actions/dependency-review-action@v4\n        with:\n          Warn-Only: true\n')}`, 'merge', 'deps', 'partial'],
    ['trivy-action Exit-Code: 1', `${both}${job("      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n          Exit-Code: '1'\n")}`, 'push', 'deps', 'covered'],
    ['trivy-action exit-code empty', `${both}${job("      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n          exit-code: ''\n")}`, 'push', 'deps', 'partial'],
    ['zap fail_action "True"', `${both}${job("      - uses: zaproxy/action-baseline@v0.14.0\n        with:\n          fail_action: 'True'\n")}`, 'merge', 'dast', 'covered'],
    ['zap default', `${both}${job('      - uses: zaproxy/action-baseline@v0.14.0\n')}`, 'merge', 'dast', 'partial'],
    ['checkov -s', `${both}${job('      - run: checkov -d . -s\n')}`, 'merge', 'iac', 'partial'],
    ['gosec --no-fail', `${both}${job('      - run: gosec --no-fail ./...\n')}`, 'push', 'sast', 'partial'],
    ['gosec action args -no-fail', `${both}${job("      - uses: securego/gosec@master\n        with:\n          args: '-no-fail -fmt sarif -out results.sarif ./...'\n")}`, 'push', 'sast', 'partial'],
    ['gosec action args (blocking)', `${both}${job("      - uses: securego/gosec@master\n        with:\n          args: './...'\n")}`, 'push', 'sast', 'covered'],
    ['govulncheck -format sarif', `${both}${job('      - run: govulncheck -format sarif ./...\n')}`, 'push', 'deps', 'partial'],
    ['govulncheck -json', `${both}${job('      - run: govulncheck -json ./...\n')}`, 'push', 'deps', 'partial'],
    ['govulncheck plain', `${both}${job('      - run: govulncheck ./...\n')}`, 'push', 'deps', 'covered'],
    ['govulncheck-action output-format sarif', `${both}${job('      - uses: golang/govulncheck-action@v1\n        with:\n          output-format: sarif\n')}`, 'push', 'deps', 'partial'],
    ['osv-scanner-action fail-on-vuln (not an input of the action)', `${both}${job('      - uses: google/osv-scanner-action/osv-scanner-action@v2\n        with:\n          fail-on-vuln: false\n')}`, 'push', 'deps', 'covered'],
    ['bandit-action exit_zero', `${both}${job('      - uses: PyCQA/bandit-action@v1\n        with:\n          exit_zero: true\n')}`, 'push', 'sast', 'partial'],
    ['bandit-action, no inputs', `${both}${job('      - uses: PyCQA/bandit-action@v1\n')}`, 'push', 'sast', 'partial'],
    ['pip-audit action allow-failure', `${both}${job('      - uses: pypa/gh-action-pip-audit@v1.1.0\n        with:\n          internal-be-careful-allow-failure: true\n')}`, 'push', 'deps', 'partial'],
    ['paths on pull_request only: merge', `on:\n  push:\n  pull_request:\n    paths: ['src/**']\n${job('      - run: gitleaks detect\n')}`, 'merge', 'secrets', 'partial'],
    ['paths on pull_request only: push', `on:\n  push:\n  pull_request:\n    paths: ['src/**']\n${job('      - run: gitleaks detect\n')}`, 'push', 'secrets', 'covered'],
    ['npm audit --audit-level=none', `${both}${job('      - run: npm audit --audit-level=none\n')}`, 'push', 'deps', 'partial'],
    ['semgrep ci || true', `${both}${job('      - run: semgrep ci || true\n')}`, 'push', 'sast', 'partial'],
    ['&& at line end, then || true', `${both}${job('      - run: |\n          trivy fs --exit-code 1 . &&\n            echo ok || true\n')}`, 'push', 'deps', 'partial'],
    ['trivy-action exit-code 1, continue-on-error expression', `${both}${job("      - uses: aquasecurity/trivy-action@0.28.0\n        continue-on-error: \${{ github.event_name == 'push' }}\n        with:\n          exit-code: '1'\n")}`, 'push', 'deps', 'partial'],
    ['step if: success() || event_name', `${both}${job("      - run: gitleaks detect\n        if: success() || github.event_name == 'push'\n")}`, 'merge', 'secrets', 'partial'],
    ['docker run with --security-opt, then version', `${both}${job('      - run: docker run --rm --security-opt x zricethezav/gitleaks:v8 version\n')}`, 'push', 'secrets', 'missing'],
    ['gitleaks version', `${both}${job('      - run: gitleaks version\n')}`, 'push', 'secrets', 'missing'],
    ['trivy --exit-code 1 --version', `${both}${job('      - run: trivy --exit-code 1 --version\n')}`, 'push', 'deps', 'missing'],
    [`set +e on a line over 4 KB, tool not last`, `${both}${job(`      - run: |\n          set +e # ${'x'.repeat(5000)}\n          gitleaks detect\n          echo done\n`)}`, 'push', 'secrets', 'partial'],
    ['bash -c with a quoted script (not read)', `${both}${job("      - run: bash -c 'gitleaks detect || true'\n")}`, 'push', 'secrets', 'missing'],
    ['|| true, then a comment', `${both}${job('      - run: gitleaks detect || true # ok\n')}`, 'push', 'secrets', 'partial'],
    ['step if: ${{ cancelled() }}', `${both}${job('      - run: gitleaks detect\n        if: \${{ cancelled() }}\n')}`, 'push', 'secrets', 'partial'],
    ['|| exit 1 still blocks', `${both}${job('      - run: gitleaks detect || exit 1\n')}`, 'push', 'secrets', 'covered'],
    ['|| { echo; exit 1; } still blocks', `${both}${job('      - run: \'gitleaks detect || { echo "::error::leaks"; exit 1; }\'\n')}`, 'push', 'secrets', 'covered'],
    ['shell: bash makes a pipe block (pipefail)', `${both}${job('      - shell: bash\n        run: gitleaks detect | tee out\n')}`, 'push', 'secrets', 'covered'],
    ['set -o pipefail makes a pipe block', `${both}${job('      - run: |\n          set -euo pipefail\n          gitleaks detect | tee out\n')}`, 'push', 'secrets', 'covered'],
    ['&& in a list before the last one (bash -e skips it)', `${both}${job('      - run: |\n          gitleaks detect && echo clean\n          echo next\n')}`, 'push', 'secrets', 'partial'],
    ['&& in the last list still fails the step', `${both}${job('      - run: |\n          echo start\n          gitleaks detect && echo clean\n')}`, 'push', 'secrets', 'covered'],
    ['set +e, tool is the last command', `${both}${job('      - run: |\n          set +e\n          gitleaks detect\n')}`, 'push', 'secrets', 'covered'],
    ['custom shell, tool is the last command', `${both}${job('      - shell: pwsh\n        run: |\n          Write-Host scanning\n          gitleaks detect\n')}`, 'push', 'secrets', 'covered'],
    ['custom shell pwsh, tool not last', `${both}${job('      - shell: pwsh\n        run: |\n          gitleaks detect\n          Write-Host done\n')}`, 'push', 'secrets', 'partial'],
    ['bash -e {0} keeps errexit', `${both}${job('      - shell: bash -e {0}\n        run: |\n          gitleaks detect\n          echo done\n')}`, 'push', 'secrets', 'covered'],
    ['defaults.run.shell applies to the job', `${both}jobs:\n  scan:\n    runs-on: x\n    defaults:\n      run:\n        shell: bash {0}\n    steps:\n      - run: |\n          gitleaks detect\n          echo done\n`, 'push', 'secrets', 'partial'],
    ['echo $(tool) hides its status', `${both}${job('      - run: echo "found $(gitleaks detect)" && echo $(gitleaks detect)\n')}`, 'push', 'secrets', 'partial'],
    ['guard naming this repo, other case', `${both}jobs:\n  scan:\n    runs-on: x\n    if: github.repository == 'O/R'\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'covered'],
    ['owner guard != this owner', `${both}jobs:\n  scan:\n    runs-on: x\n    if: github.repository_owner != 'o'\n    steps:\n      - run: gitleaks detect\n`, 'push', 'secrets', 'missing'],
    ['command (no -v) is a wrapper', `${both}${job('      - run: command gitleaks detect\n')}`, 'push', 'secrets', 'covered'],
  ];
  for (const [label, body, layer, id, want] of cases) {
    it(`coverage: round 2: ${label} → ${want}`, async () => {
      const r = await one(body, layer, id, runnableTf, id === 'secrets' || id === 'iac' ? undefined : 'app');
      expect(r.status).toBe(want);
    });
  }

  it('coverage: round 2 hooks: husky runs with sh -e, lefthook with sh -c (no -e)', async () => {
    const husky = makeTempDir();
    writeIn(husky, '.husky/pre-commit', 'gitleaks protect --staged\necho done\n');
    expect(row(await coverage(husky), 'pre-commit', 'secrets').status).toBe('covered');
    const lefthook = makeTempDir();
    writeIn(lefthook, 'lefthook.yml', 'pre-commit:\n  commands:\n    leaks:\n      run: gitleaks protect --staged; echo done\n');
    expect(row(await coverage(lefthook), 'pre-commit', 'secrets').status).toBe('partial');
  });
});

describe('mapCoverage (fix round 3)', () => {
  const step = (script: string) => `${both}${job(`      - run: |\n${script.split('\n').map((l) => `          ${l}`).join('\n')}\n`)}`;
  const cases: [string, string, Layer, string, Coverage['status']][] = [
    // N1: `&` inside a redirection is part of the word, not a list end
    ['2>&1 || true', step('gitleaks detect 2>&1 || true'), 'push', 'secrets', 'partial'],
    ['2>&1 | tee (default shell)', step('gitleaks detect 2>&1 | tee report.txt'), 'push', 'secrets', 'partial'],
    ['&>/dev/null || true', step('gitleaks detect &>/dev/null || true'), 'push', 'secrets', 'partial'],
    ['> out.txt 2>&1 || echo', step('gitleaks detect > out.txt 2>&1 || echo "leaks"'), 'push', 'secrets', 'partial'],
    ['set +e, then tool 2>&1 as the last command', step('set +e\ngitleaks detect 2>&1'), 'push', 'secrets', 'covered'],
    ['tool 2>&1 alone', step('gitleaks detect 2>&1'), 'push', 'secrets', 'covered'],
    ['>&2 and &>> keep the run blocking', step('gitleaks detect >&2\ngitleaks detect &>> log.txt\necho done'), 'push', 'secrets', 'covered'],
    ['|& is a pipe', step('gitleaks detect |& tee out.txt'), 'push', 'secrets', 'partial'],
    ['a redirection before the command', step('> out.txt gitleaks detect'), 'push', 'secrets', 'covered'],
    // U8: background &
    ['background &, then wait', step('gitleaks detect &\nwait'), 'push', 'secrets', 'partial'],
    ['a && b & in the background', step('echo start && gitleaks detect &\nwait'), 'push', 'secrets', 'partial'],
    // U8: a { in argument position is not a group
    ['stray { in an argument inside a group', step('{ gitleaks detect; echo {a; } || true'), 'push', 'secrets', 'partial'],
    ['xargs -I {} keeps {} as a word (xargs, the last stage, fails when the tool does)', step('ls | xargs -I {} gitleaks detect --source {} ; echo done'), 'push', 'secrets', 'covered'],
    ['a { … } group as a command still groups', step('{ gitleaks detect; echo x; } || true'), 'push', 'secrets', 'partial'],
    // U8: backticks
    ['backtick substitution', step('echo `gitleaks detect`'), 'push', 'secrets', 'partial'],
    ['VAR=`tool` keeps its status', step('out=`gitleaks detect`\necho "$out"'), 'push', 'secrets', 'covered'],
    // U8: here-documents are data
    ["here-doc body (<<'EOF')", step("cat > scan.sh <<'EOF'\ngitleaks detect\nEOF\necho written"), 'push', 'secrets', 'missing'],
    ['here-doc body (<<-EOF, tabs)', step('cat <<-EOF\n\tgitleaks detect\n\tEOF\necho written'), 'push', 'secrets', 'missing'],
    ['here-doc body (<< "EOF", spaced)', step('cat << "EOF" > x\ngitleaks detect\nEOF'), 'push', 'secrets', 'missing'],
    ["here-doc with an apostrophe, then tool || true", step("cat <<EOF\nDon't panic\nEOF\ngitleaks detect || true"), 'push', 'secrets', 'partial'],
    ['here-doc, then a blocking tool', step('cat <<EOF > notes.txt\nhello\nEOF\ngitleaks detect'), 'push', 'secrets', 'covered'],
    ['unterminated here-doc hides the rest', step('cat <<EOF\ngitleaks detect'), 'push', 'secrets', 'missing'],
    ['here-string <<< is not a here-doc', step('cat <<< "x"\ngitleaks detect'), 'push', 'secrets', 'covered'],
    // U8: function bodies
    ['function defined, called with || echo', step('scan() { gitleaks detect --redact; }\nscan || echo "leaks"'), 'push', 'secrets', 'partial'],
    ['function keyword', step('function scan {\n  gitleaks detect\n}\nscan'), 'push', 'secrets', 'partial'],
    ['a tool after a function definition still counts', step('log() { echo "$@"; }\ngitleaks detect'), 'push', 'secrets', 'covered'],
    // U8: ( set -e ) and ( cd ) stay in their subshell
    ['( set -e ) does not restore errexit outside', step('set +e\n( set -e )\ngitleaks detect\necho done'), 'push', 'secrets', 'partial'],
    ['set -e in a { } group does apply after it', step('set +e\n{ set -e; }\ngitleaks detect\necho done'), 'push', 'secrets', 'covered'],
  ];
  for (const [label, body, layer, id, want] of cases) {
    it(`coverage: round 3: ${label} → ${want}`, async () => {
      expect((await one(body, layer, id)).status).toBe(want);
    });
  }

  it('coverage: round 3: ( cd x ) stays in its subshell', async () => {
    const services = [svc('apps/api'), svc('apps/web')];
    const r = await one(step('(cd apps/web && npm run lint)\nnpm test'), 'push', 'unit-tests', { services, monorepo: 'npm-workspaces' }, 'api');
    expect(r.status).toBe('covered'); // npm test ran at the root, which covers every service
  });

  it('coverage: round 3: input spellings that differ only in case: a soft one wins', async () => {
    const st = async (lines: string) => (await one(`${both}${job(`      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n${lines}`)}`, 'push', 'deps', {}, 'app')).status;
    expect(await st("          exit-code: '1'\n          EXIT-CODE: '0'\n")).toBe('partial');
    expect(await st("          EXIT-CODE: '0'\n          exit-code: '1'\n")).toBe('partial');
    expect(await st("          exit-code: '1'\n          Exit-Code: '2'\n")).toBe('covered');
  });

  it('coverage: round 3: Windows runners default to pwsh (the tool must be the last command)', async () => {
    const win = (runsOn: string, extra = '', steps = '      - run: |\n          gitleaks detect\n          git status\n') =>
      `${both}jobs:\n  scan:\n    runs-on: ${runsOn}\n${extra}    steps:\n${steps}`;
    expect((await one(win('windows-latest'), 'push', 'secrets')).status).toBe('partial');
    expect((await one(win('[self-hosted, Windows]'), 'push', 'secrets')).status).toBe('partial');
    expect((await one(win('${{ matrix.os }}', '    strategy:\n      matrix:\n        os: [ubuntu-latest, windows-latest]\n'), 'push', 'secrets')).status).toBe('partial');
    expect((await one(win('ubuntu-latest'), 'push', 'secrets')).status).toBe('covered');
    // an explicit shell: bash on Windows keeps bash's rules
    expect((await one(win('windows-latest', '', '      - shell: bash\n        run: |\n          gitleaks detect\n          git status\n'), 'push', 'secrets')).status).toBe('covered');
  });
});

describe('mapCoverage (fix round 4)', () => {
  const step = (script: string) => `${both}${job(`      - run: |\n${script.split('\n').map((l) => `          ${l}`).join('\n')}\n`)}`;
  const cases: [string, string, Coverage['status']][] = [
    // R1: a `}` straight after done / fi / esac closes the group
    ['{ for …; done } || true', '{ for x in a; do gitleaks detect; done } || true', 'partial'],
    ['{ if …; fi } || true', '{ if true; then gitleaks detect; fi } || true', 'partial'],
    ['{ case …; esac } || true', '{ case x in x) gitleaks detect;; esac } || true', 'partial'],
    // A compound command takes on what follows it, as a group does
    ['for …; done || true', 'for x in a; do gitleaks detect; done || true', 'partial'],
    ['if …; fi || true', 'if true; then gitleaks detect; fi || true', 'partial'],
    ['case …; esac || true', 'case x in (x|y) gitleaks detect;; esac || true', 'partial'],
    ['for …; done | tee (no pipefail)', 'for x in a; do gitleaks detect; done | tee out', 'partial'],
    ['for …; done & (background)', 'for x in a; do gitleaks detect; done &\nwait', 'partial'],
    ['if …; fi && echo, not the last list', 'if true; then gitleaks detect; fi && echo ok\necho next', 'partial'],
    ['a multi-line if body still blocks', 'if true; then\n  gitleaks detect\nfi\necho next', 'covered'],
    ['a for body still blocks', 'for x in a; do gitleaks detect; done\necho next', 'covered'],
    // case arms: a pattern is not a command; the arm's body is
    ['a case arm body blocks', 'case "$E" in\n  push) gitleaks detect ;;\nesac\necho done', 'covered'],
    ['a case pattern is not a command', 'case "$1" in\n  a) echo ;;\n  gitleaks) echo hi ;;\nesac', 'missing'],
    ['a reserved word in argument position is a plain word', 'if x; then gitleaks detect; echo then if; fi || true', 'partial'],
    ['a function whose body is a for loop', 'f() for x in a; do gitleaks detect; done\necho next', 'partial'],
    // bash reads this `}` as an argument of echo, so the group ends on the next line and the tool's failure stops the step
    ['a } after $( … ) is an argument', '{ gitleaks detect; echo $(date) } || true\n}', 'covered'],
    // R3: << inside $(( … )) or (( … )) is a shift, not a here-document
    ['$(( 1 << 2 )) inside a group || true', '{\n  gitleaks detect\n  echo $((1 << 2))\n} || true', 'partial'],
    ['(( x <<= 1 )), then tool || true', '(( x <<= 1 ))\ngitleaks detect || true', 'partial'],
    ['for (( … << … )), then tool || true', 'for ((i = 1 << 2; i < 9; i++)); do :; done\ngitleaks detect || true', 'partial'],
    ['$(( ( … ) << … )), then tool || true', 'x=$(( (1 + 2) << 3 ))\ngitleaks detect || true', 'partial'],
    ['a here-doc after arithmetic is still a here-doc', 'echo $((1 << 2))\ncat <<EOF\ngitleaks detect\nEOF', 'missing'],
    ['a $( … ) inside arithmetic is a command again', 'echo $(( $(echo ")") ))\ngitleaks detect || true', 'partial'],
  ];
  for (const [label, script, want] of cases) {
    it(`coverage: round 4: ${label} → ${want}`, async () => {
      expect((await one(step(script), 'push', 'secrets')).status).toBe(want);
    });
  }

  const trivy = (lines: string[]) => `${both}${job(`      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n${lines.map((l) => `          ${l}\n`).join('')}`)}`;
  /** n distinct spellings of a 16-letter name that differ only in case. */
  const spellings = (n: number) => Array.from({ length: n }, (_, i) => Array.from('abcdefghijklmnop', (ch, b) => ((i >> b) & 1 ? ch.toUpperCase() : ch)).join(''));

  it('coverage: round 4: more spellings of one input than pipegen keeps → partial, never covered', async () => {
    // exit-code has 9 letters: 2^9 case spellings; each sets the failing value '1'
    const variants = (n: number) => Array.from({ length: n }, (_, i) => Array.from('exit-code', (ch, b) => ((i >> b) & 1 ? ch.toUpperCase() : ch)).join(''));
    expect((await one(trivy(variants(8).map((k) => `${k}: '1'`)), 'push', 'deps', {}, 'app')).status).toBe('covered');
    const r = await one(trivy(variants(9).map((k) => `${k}: '1'`)), 'push', 'deps', {}, 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toBe('The trivy check runs, but its step sets more inputs than pipegen reads, so pipegen can\'t tell whether it blocks anything.');
  });

  it('coverage: round 4: a step with more inputs than pipegen reads → partial, never covered', async () => {
    const filler = (n: number) => spellings(n).map((k) => `${k}: x`);
    expect((await one(trivy(["exit-code: '1'", ...filler(255)]), 'push', 'deps', {}, 'app')).status).toBe('covered');
    const r = await one(trivy(["exit-code: '1'", ...filler(256)]), 'push', 'deps', {}, 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/sets more inputs than pipegen reads/);
  });

  it('coverage: round 4: a 30,000-key with: map is read in linear time', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', trivy(["exit-code: '1'", ...spellings(30_000).map((k) => `${k}: 1`)]));
    const t = performance.now();
    const p = await profileOf(dir);
    expect(p.existingWorkflows).toHaveLength(1); // under the 1 MB read limit, so it really is read
    const r = row(await mapCoverage(p, floorNeeds(p, caps), dir), 'push', 'deps', 'app');
    const ms = performance.now() - t;
    expect(r.status).toBe('partial');
    expect(ms).toBeLessThan(5000);
  });
});

describe('mapCoverage (fix round 5)', () => {
  const TOO_MANY = "There are too many services or workflow steps to check in full, so pipegen can't tell.";
  const services = (n: number) => Array.from({ length: n }, (_, i) => svc(`apps/s${i}`));
  /** A tool run in its own subshell, so every hit keeps a concrete dir. */
  const inDir = (d: string, cmd = 'semgrep ci') => `(cd ${d} && ${cmd})`;
  /** One workflow file per `perFile` lines, each file one step. */
  function cdWorkflows(dir: string, cmds: string[], perFile: number): void {
    for (let f = 0; f * perFile < cmds.length; f++) {
      const lines = cmds.slice(f * perFile, (f + 1) * perFile).map((c) => `          ${c}`).join('\n');
      wf(dir, `w${f}.yml`, `${both}jobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n${lines}\n`);
    }
  }
  async function cdCoverage(cmds: string[], svcs: Service[], perFile = 20_000) {
    const dir = makeTempDir();
    cdWorkflows(dir, cmds, perFile);
    const p = await profileOf(dir, { services: svcs, monorepo: 'npm-workspaces' });
    expect(p.existingWorkflows).toHaveLength(Math.ceil(cmds.length / perFile)); // each file is under the 1 MB read limit
    const t = performance.now();
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir);
    return { rows, ms: performance.now() - t };
  }

  it('coverage: round 5: 2,000 services and 100,000 hits in 8,000 dirs finish in under 5 s', async () => {
    const svcs = [...services(2000), svc('other/lonely')];
    const cmds = Array.from({ length: 100_000 }, (_, k) => inDir(`apps/s${k % 2000}/d${Math.floor(k / 2000) % 4}`));
    const { rows, ms } = await cdCoverage(cmds, svcs);
    expect(ms).toBeLessThan(5000);
    expect(row(rows, 'push', 'sast', 's0')).toMatchObject({ status: 'covered', by: 'semgrep', where: '.github/workflows/w0.yml (job j)' });
    expect(row(rows, 'merge', 'sast', 's1999')).toMatchObject({ status: 'covered', by: 'semgrep' });
    expect(row(rows, 'push', 'sast', 'lonely').status).toBe('missing'); // under the caps, a gap is still a gap
  }, 60_000);

  it('coverage: round 5: more step dirs than pipegen checks → unknown, never covered or missing', async () => {
    const svcs = [svc('apps/a'), svc('apps/b')];
    const filler = (n: number) => Array.from({ length: n }, (_, i) => inDir(`x/${i}`));
    // at the cap, the run in apps/a still counts
    const under = (await cdCoverage([...filler(9_999), inDir('apps/a')], svcs)).rows;
    expect(row(under, 'push', 'sast', 'a').status).toBe('covered');
    expect(row(under, 'push', 'sast', 'b').status).toBe('missing');
    // one dir over: the run in apps/a is not checked, so neither service can be called covered or missing
    const over = (await cdCoverage([...filler(10_000), inDir('apps/a')], svcs)).rows;
    for (const s of ['a', 'b']) expect(row(over, 'push', 'sast', s)).toEqual(expect.objectContaining({ status: 'unknown', why: TOO_MANY }));
    expect(over.some((r) => r.need.service !== undefined && r.status === 'missing' && r.need.layer !== 'pre-commit')).toBe(false);
    // repo-wide rows don't depend on where a step ran: every run still counts for them
    expect(row(over, 'push', 'secrets').status).toBe('missing');
  }, 60_000);

  it('coverage: round 5: more services than pipegen checks → unknown, never covered or missing', async () => {
    // eslint runs in apps/s0 only; semgrep runs at the repo root
    const run = (n: number) => cdCoverage([inDir('apps/s0', 'npx eslint .'), inDir('.')], services(n));
    const under = (await run(5_000)).rows;
    expect(row(under, 'push', 'lint', 's0').status).toBe('covered');
    expect(row(under, 'push', 'lint', 's1').status).toBe('missing');
    const { rows: over, ms } = await run(5_001);
    expect(ms).toBeLessThan(5000);
    for (const s of ['s0', 's1', 's5000']) expect(row(over, 'push', 'lint', s)).toEqual(expect.objectContaining({ status: 'unknown', why: TOO_MANY }));
    // a run at the repo root covers every service whatever their number
    for (const s of ['s0', 's1', 's5000']) expect(row(over, 'push', 'sast', s).status).toBe('covered');
  }, 120_000);
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
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n    commandFails: flag\n')).toThrow(/not valid/); // flag needs failFlags
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    actions: [o/a]\n    actionFails: input\n')).toThrow(/not valid/); // input needs failInputs
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n    softFlags: [exit-zero]\n')).toThrow(/not valid/); // not a flag
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n    partialWhy: lower case and no stop\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    actions: [o/a*/b]\n')).toThrow(/not valid/); // * only on the last part
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n  - id: a\n    categories: [sast]\n    commands: [b]\n')).toThrow(/not valid/);
  });
});

// ---------- Task 5: accuracy from real repos (express, flask, left-pad shapes; minimal hand-written fixtures) ----------

const pkg = (dir: string, scripts: Record<string, string>, at = 'package.json') => writeIn(dir, at, JSON.stringify({ name: 'app', scripts }));
const ci = (dir: string, steps: string, extra = '') => wf(dir, 'ci.yml', `${both}${job(steps, extra)}`);

describe('mapCoverage (Task 5, item 1: own scripts by name and content)', () => {
  it('own scripts: npm run test-ci → covered "your own `npm run test-ci`" (express shape: nyc wraps npm test, which runs mocha)', async () => {
    const dir = makeTempDir();
    pkg(dir, {
      test: 'mocha --require test/support/env --reporter spec --check-leaks test/ test/acceptance/',
      'test-ci': 'nyc --exclude examples --exclude test --exclude benchmarks --reporter=lcovonly --reporter=text npm test',
      lint: 'eslint .', 'lint:fix': 'eslint . --fix',
    });
    ci(dir, '      - shell: bash\n        run: npm run test-ci\n');
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run test-ci`', where: '.github/workflows/ci.yml (job scan)' });
    expect(row(rows, 'merge', 'full-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run test-ci`' });
    expect(row(rows, 'push', 'unit-tests', 'app').why).toBe('Your own `npm run test-ci` runs on every push.');
  });

  it('own scripts: any script name counts when its content runs a known test or lint tool (yarn, pnpm and bun too)', async () => {
    const dir = makeTempDir();
    pkg(dir, { ci: 'vitest run --coverage', check: 'eslint . && prettier --check .' });
    ci(dir, run('yarn run ci --silent -- --coverage') + run('pnpm run check'));
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `yarn run ci`' });
    expect(row(rows, 'push', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'your own `pnpm run check`' });
  });

  it('own scripts: the script is read where the command runs (working-directory)', async () => {
    const dir = makeTempDir();
    pkg(dir, { 'test-unit': 'jest' }, 'api/package.json');
    ci(dir, '      - run: bun run test-unit\n        working-directory: api\n');
    const rows = await coverage(dir, { services: [svc('api'), svc('web')] });
    expect(row(rows, 'push', 'unit-tests', 'api')).toMatchObject({ status: 'covered', by: 'your own `bun run test-unit`' });
    expect(row(rows, 'push', 'unit-tests', 'web').status).toBe('missing');
    // a root script that changes into one service tests that service only
    const dir2 = makeTempDir();
    pkg(dir2, { 'test-api': 'cd api && jest' });
    ci(dir2, run('npm run test-api'));
    const rows2 = await coverage(dir2, { services: [svc('api'), svc('web')] });
    expect(row(rows2, 'push', 'unit-tests', 'api')).toMatchObject({ status: 'covered', by: 'your own `npm run test-api`' });
    expect(row(rows2, 'push', 'unit-tests', 'web').status).toBe('missing');
  });

  it('own scripts (adversarial): a test- script that runs echo, mentions a tool in quotes, is missing, or has no package.json → missing', async () => {
    for (const [scripts, cmd] of [
      [{ 'test-ci': 'echo skip' }, 'npm run test-ci'],
      [{ 'test-ci': 'echo mocha && echo "jest"' }, 'npm run test-ci'],
      [{ 'test-ci': 'echo "$(mocha)"' }, 'npm run test-ci'],
      [{ other: 'mocha' }, 'npm run test-ci'],
      [{ 'test-ci': 'mocha' }, 'npm run test-cj --if-present'],
      [null, 'npm run test-ci'],
      [{ ci: 'node build.js' }, 'npm run ci'],
      [{ 'test-ci': 'mocha' }, 'npm run test-ci --workspace=other'],
      [{ 'test-ci': 'mocha' }, 'pnpm run test-ci --filter other'],
    ] as [Record<string, string> | null, string][]) {
      const dir = makeTempDir();
      if (scripts !== null) pkg(dir, scripts);
      ci(dir, run(cmd));
      const rows = await coverage(dir);
      expect(row(rows, 'push', 'unit-tests', 'app').status, `${cmd} ${JSON.stringify(scripts)}`).toBe('missing');
      expect(row(rows, 'push', 'lint', 'app').status).toBe('missing');
    }
  });

  it("own scripts (adversarial): a script whose tool can't fail the step → partial (npm runs scripts with sh -c, no -e)", async () => {
    for (const body of ['vitest run || true', 'vitest run; echo done', 'vitest run | tee out.txt', 'nyc --zzz vitest echo hi']) {
      const dir = makeTempDir();
      pkg(dir, { 'test-ci': body });
      ci(dir, run('npm run test-ci'));
      const status = row(await coverage(dir), 'push', 'unit-tests', 'app').status;
      expect(status, body).toBe(body.startsWith('nyc') ? 'missing' : 'partial'); // an nyc flag pipegen doesn't know: no command
    }
    // the step's own suppression applies on top
    const dir = makeTempDir();
    pkg(dir, { 'test-ci': 'vitest run' });
    ci(dir, run('npm run test-ci || true'));
    expect(row(await coverage(dir), 'push', 'unit-tests', 'app').status).toBe('partial');
  });

  it('own scripts (adversarial): scripts that only fix (lint:fix, lint-fix, format:write) are not checks; a script cycle ends', async () => {
    const dir = makeTempDir();
    pkg(dir, { 'lint:fix': 'eslint . --fix', 'lint-fix': 'eslint . --fix', 'format:write': 'prettier --write .', a: 'npm run b', b: 'npm run a' });
    ci(dir, run('npm run lint:fix') + run('npm run lint-fix') + run('pnpm lint:fix') + run('npm run format:write') + run('npm run a'));
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'lint', 'app').status).toBe('missing');
    expect(row(rows, 'push', 'unit-tests', 'app').status).toBe('missing');
  });

  it('own scripts (adversarial): a chain of scripts that each call the next one twice is read in linear time, capped', async () => {
    const dir = makeTempDir();
    const scripts: Record<string, string> = {};
    for (let i = 0; i < 1000; i++) scripts[`s${i}`] = `npm run s${i + 1} && npm run s${i + 1} || npm run s${i + 1}`;
    scripts.s1000 = 'vitest run';
    pkg(dir, scripts);
    ci(dir, run('npm run s0'));
    const started = Date.now();
    const status = row(await coverage(dir), 'push', 'unit-tests', 'app').status;
    expect(Date.now() - started).toBeLessThan(3000);
    expect(status).toBe('missing'); // past the script cap nothing is counted
  });

  it('own scripts: a husky hook running an own script is read the same way', async () => {
    const dir = makeTempDir();
    pkg(dir, { 'lint-staged-check': 'lint-staged' });
    writeIn(dir, '.husky/pre-commit', 'npm run lint-staged-check\n');
    expect(row(await coverage(dir), 'pre-commit', 'format-lint', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run lint-staged-check`' });
  });
});

describe('mapCoverage (Task 5, item 2: Python runners)', () => {
  it('python runners: flask shape `uv run --locked --no-default-groups --group dev tox run` → covered "your own `tox run`"', async () => {
    const dir = makeTempDir();
    ci(dir, run('uv run --locked --no-default-groups --group dev tox run'));
    const rows = await coverage(dir);
    expect(row(rows, 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `tox run`' });
    expect(row(rows, 'merge', 'full-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `tox run`' });
  });

  it('python runners: tox, tox -p, nox, and pytest through poetry, pipenv, hatch, pdm and uv', async () => {
    for (const [cmd, by] of [
      ['tox', 'your own `tox`'], ['tox -p', 'your own `tox`'], ['tox r', 'your own `tox r`'], ['python -m tox', 'your own `tox`'], ['nox', 'your own `nox`'],
      ['poetry run pytest -q', 'your own `pytest`'], ['pipenv run pytest', 'your own `pytest`'], ['hatch run pytest', 'your own `pytest`'],
      ['pdm run pytest', 'your own `pytest`'], ['uv run -p 3.12 --with pytest-cov pytest', 'your own `pytest`'], ['uv run -- pytest', 'your own `pytest`'],
    ]) {
      const dir = makeTempDir();
      ci(dir, run(cmd as string));
      expect(row(await coverage(dir), 'push', 'unit-tests', 'app'), cmd).toMatchObject({ status: 'covered', by });
    }
  });

  it('python runners (adversarial): uv run wrapping something that is not a test runner, and tox or nox runs that pick other envs → missing', async () => {
    for (const steps of [
      run('uv run --group dev python scripts/build.py'), run('uv run --with ruff python -c pass'), run('uv run --with pytest python -c pass'),
      run('uv run --some-new-flag pytest'), run('uv run -qx pytest'), run('tox run -e typing'), run('tox -e py312'), run('tox list'), run('tox run --notest'),
      run('tox -re lint'), run('tox --override testenv.commands=true'), run('nox -s lint'), run('nox --list'), run('nox -k lint'), run('TOXENV=lint tox'),
      '      - run: tox run\n        env:\n          TOX_ENV: lint\n', '      - run: tox run\n        env:\n          TOXENV: lint\n',
      '      - run: nox\n        env:\n          NOXSESSION: lint\n', run('echo "TOXENV=lint" >> "$GITHUB_ENV"') + run('tox run'),
    ]) {
      const dir = makeTempDir();
      ci(dir, steps);
      expect(row(await coverage(dir), 'push', 'unit-tests', 'app').status, steps).toBe('missing');
    }
    // an env set for the whole job or workflow picks the envs too
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}env:\n  TOX_ENV: lint\n${job(run('tox run'))}`);
    expect(row(await coverage(dir), 'push', 'unit-tests', 'app').status).toBe('missing');
    const dir2 = makeTempDir();
    ci(dir2, run('tox run'), '    env:\n      TOX_ENV: lint\n');
    expect(row(await coverage(dir2), 'push', 'unit-tests', 'app').status).toBe('missing');
  });
});

const RUFF_REPO = 'https://github.com/astral-sh/ruff-pre-commit';
const hookConfig = (hooks: string, repo = RUFF_REPO) => `repos:\n  - repo: ${repo}\n    rev: v0.16.0\n    hooks:\n${hooks}`;
const FLASK_PRECOMMIT = 'uv run --locked --no-default-groups --group pre-commit pre-commit run --show-diff-on-failure --color=always --all-files';

describe('mapCoverage (Task 5, item 3: pre-commit hook contents)', () => {
  it('pre-commit hooks: ruff-check and ruff-format hooks → the format and lint hook is covered', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n      - id: ruff-format\n'));
    const rows = await coverage(dir);
    expect(row(rows, 'pre-commit', 'format-lint', 'app')).toMatchObject({ status: 'covered', by: 'ruff', where: '.pre-commit-config.yaml' });
    expect(row(rows, 'pre-commit', 'hooks')).toMatchObject({ status: 'covered', by: 'pre-commit' });
  });

  it('pre-commit hooks: CI running `pre-commit run --all-files` (also through uv run) covers lint with the hooks\' tools (flask shape)', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n      - id: ruff-format\n'));
    wf(dir, 'pre-commit.yaml', `on:\n  pull_request:\n  push:\n    branches: [main, stable]\n${job(run(FLASK_PRECOMMIT))}`);
    const rows = await coverage(dir);
    expect(row(rows, 'merge', 'hooks-ci')).toMatchObject({ status: 'covered', by: 'pre-commit' });
    expect(row(rows, 'push', 'hooks-ci').status).toBe('partial'); // feature-branch pushes don't run it
    const lint = row(rows, 'merge', 'lint', 'app');
    expect(lint).toMatchObject({ status: 'covered', by: 'ruff', where: '.github/workflows/pre-commit.yaml (job scan) → .pre-commit-config.yaml' });
    expect(lint.why).toBe('The ruff check in the pre-commit hooks runs on every pull request.');
    expect(row(rows, 'push', 'lint', 'app').status).toBe('partial');
    // the pre-commit/action runs `pre-commit run --all-files` by default
    const dir2 = makeTempDir();
    writeIn(dir2, '.pre-commit-config.yaml', hookConfig('      - id: ruff\n'));
    ci(dir2, '      - uses: pre-commit/action@v3.0.1\n');
    expect(row(await coverage(dir2), 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'ruff' });
  });

  it('pre-commit hooks (adversarial): a manual stage, a local hook named like a tool, a look-alike repo, an overridden entry → not covered', async () => {
    // fix round 1 (I2): a hook set up for another stage is partial (set up, but not run before a commit), never covered
    for (const [config, expected] of [
      [hookConfig('      - id: ruff-check\n        stages: [manual]\n'), 'partial'],
      [`default_stages: [pre-push]\n${hookConfig('      - id: ruff-format\n')}`, 'partial'],
      ['repos:\n  - repo: local\n    hooks:\n      - id: ruff\n        name: ruff\n        entry: echo ruff\n        language: system\n', 'missing'],
      ['repos:\n  - repo: local\n    hooks:\n      - id: gitleaks\n        name: gitleaks\n        entry: "true"\n        language: system\n', 'missing'],
      [hookConfig('      - id: ruff-check\n', 'https://github.com/someone/ruff-pre-commit'), 'missing'],
      [hookConfig('      - id: ruff-check\n        entry: echo skipped\n'), 'missing'],
    ] as const) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', config);
      const rows = await coverage(dir);
      expect(row(rows, 'pre-commit', 'format-lint', 'app').status, config).toBe(expected);
      expect(row(rows, 'pre-commit', 'secrets').status, config).toBe('missing');
    }
  });

  it('pre-commit hooks (adversarial): CI runs that check no files, one hook, another stage or skip hooks don\'t cover lint', async () => {
    const config = hookConfig('      - id: ruff-check\n');
    for (const steps of [
      run('pre-commit run'), run('pre-commit run ruff-check --all-files'), run('pre-commit run --hook-stage manual --all-files'),
      run('pre-commit run --files a.py'), run('pre-commit run -c other.yaml --all-files'), run('SKIP=ruff-check pre-commit run --all-files'),
      '      - run: pre-commit run --all-files\n        env:\n          SKIP: ruff-check\n', run('echo "SKIP=ruff-check" >> "$GITHUB_ENV"') + run('pre-commit run --all-files'),
      "      - uses: pre-commit/action@v3.0.1\n        with:\n          extra_args: ruff-check --all-files\n",
      "      - uses: pre-commit/action@v3.0.1\n        with:\n          extra_args: ${{ inputs.args }}\n",
    ]) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', config);
      ci(dir, steps);
      expect(row(await coverage(dir), 'merge', 'lint', 'app').status, steps).toBe('missing');
    }
  });

  it('pre-commit hooks (adversarial): a secret-scan hook run in CI is not a CI secret scan (it scans staged changes); soft hook args → partial', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: gitleaks\n', 'https://github.com/gitleaks/gitleaks'));
    ci(dir, run('pre-commit run --all-files'));
    const rows = await coverage(dir);
    expect(row(rows, 'pre-commit', 'secrets')).toMatchObject({ status: 'covered', by: 'gitleaks' });
    expect(row(rows, 'merge', 'secrets').status).toBe('missing');
    const dir2 = makeTempDir();
    writeIn(dir2, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n        args: [--exit-zero]\n'));
    ci(dir2, run('pre-commit run --all-files'));
    expect(row(await coverage(dir2), 'merge', 'lint', 'app').status).toBe('partial');
  });
});

describe('mapCoverage (Task 5, item 4: package publishing at the deploy layer)', () => {
  const pkgService = { services: [svc('.', { scripts: ['test'] })] };
  const tagPush = 'on:\n  push:\n    tags: [\'*\']\n';

  it('deploy: pypa/gh-action-pypi-publish with trusted publishing → attestation covered (flask shape)', async () => {
    const dir = makeTempDir();
    wf(dir, 'publish.yaml', `${tagPush}${job('      - uses: pypa/gh-action-pypi-publish@v1.14.2\n        with:\n          packages-dir: "dist/"\n', `    permissions:\n      ${'id-' + 'token'}: write\n`)}`); // built at runtime (secret-literal guard)
    expect(row(await coverage(dir, pkgService), 'deploy', 'attestation', 'app')).toMatchObject({ status: 'covered', by: 'pypi-publish' });
  });

  it('deploy (adversarial): pypi-publish with a password, attestations off or another index makes no attestation → missing', async () => {
    for (const w of [`${'pass' + 'word'}: \${{ secrets.${'PYPI_' + 'TOKEN'} }}`, 'attestations: false', 'Attestations: "false"', 'attestations: ${{ inputs.attest }}', 'repository-url: https://pypi.example.test/legacy/', 'repository_url: https://pypi.example.test/legacy/']) {
      const dir = makeTempDir();
      wf(dir, 'publish.yaml', `${tagPush}${job(`      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          ${w}\n`)}`);
      expect(row(await coverage(dir, pkgService), 'deploy', 'attestation', 'app').status, w).toBe('missing');
    }
    const ok = makeTempDir();
    wf(ok, 'publish.yaml', `${tagPush}${job('      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          repository-url: https://test.pypi.org/legacy/\n')}`);
    expect(row(await coverage(ok, pkgService), 'deploy', 'attestation', 'app').status).toBe('covered');
  });

  it('deploy: `npm publish --provenance` on release → attestation covered', async () => {
    const dir = makeTempDir();
    wf(dir, 'npm-publish.yml', `on:\n  release:\n    types: [published]\n${job(run('npm publish --provenance --access public'))}`);
    expect(row(await coverage(dir, pkgService), 'deploy', 'attestation', 'app')).toMatchObject({ status: 'covered', by: 'npm-provenance' });
  });

  it('deploy (adversarial): --provenance inside an echo, off, in a dry run, or plain npm publish → missing', async () => {
    for (const cmd of ['echo npm publish --provenance', 'echo "npm publish --provenance"', 'npm publish', 'npm publish --provenance=false', 'npm publish --provenance false',
      'npm publish --no-provenance', 'npm publish --provenance --dry-run', 'npm stage publish --tag latest', 'npm publish --provenance --help']) {
      const dir = makeTempDir();
      wf(dir, 'npm-publish.yml', `on:\n  release:\n    types: [published]\n${job(run(cmd))}`);
      expect(row(await coverage(dir, pkgService), 'deploy', 'attestation', 'app').status, cmd).toBe('missing');
    }
  });
});

// ---------- Task 5 fix round 1: the review's probes (task-5-review.md C1, C2, I1–I4, M1–M3) ----------

describe('mapCoverage (Task 5 fix round 1)', () => {
  const py = { services: [svc('.', { language: 'python', packageManager: 'uv', scripts: [] })] };
  const PR = (steps: string) => `on:\n  pull_request:\n${job(steps)}`;

  it('C1: pypi-publish counts only at v1.11.0 or later; an older version is missing with its own why, an unknown ref partial', async () => {
    const pub = (ref: string, w = '') => `on:\n  release:\n    types: [published]\n${job(`      - uses: pypa/gh-action-pypi-publish@${ref}\n${w}`)}`;
    const pkgService = { services: [svc('.', { scripts: ['test'] })] };
    const OLD = 'The PyPI publish action runs at a version before v1.11.0, which makes no attestation unless told to.';
    const UNKNOWN = "The PyPI publish action makes attestations by default only from v1.11.0, and pipegen can't tell which version this ref is.";
    for (const [ref, status, why] of [
      ['v1.8.14', 'missing', OLD], ['v1.10.3', 'missing', OLD], ['release/v1.10', 'missing', OLD], ['release/v1.4', 'missing', OLD],
      ['dc37677b2e1c63e2034f94d8a5b11f265b73ba33', 'covered', null], // flask's pin: v1.14.2
      ['fb13cb306901256ace3dab689990e13a5550ffaa', 'covered', null], // v1.11.0
      ['release/v1', 'covered', null], ['unstable/v1', 'covered', null], ['v1.12.4', 'covered', null], ['v1.11', 'covered', null], ['release/v1.11', 'covered', null],
      ['0123456789abcdef0123456789abcdef01234567', 'partial', UNKNOWN], ['main', 'partial', UNKNOWN], ['v2.0.0', 'partial', UNKNOWN],
      ['release/v1.12.1', 'partial', UNKNOWN], ['${{ inputs.ref }}', 'partial', UNKNOWN],
    ] as const) {
      const dir = makeTempDir();
      wf(dir, 'publish.yml', pub(ref));
      const r = row(await coverage(dir, pkgService), 'deploy', 'attestation', 'app');
      expect(r.status, ref).toBe(status);
      if (why !== null) expect(r.why, ref).toBe(why);
      if (status === 'missing') expect(r).toMatchObject({ by: 'pypi-publish', where: '.github/workflows/publish.yml (job scan)' });
    }
    for (const value of ['false', '"False"', '"FALSE"']) {
      const dir = makeTempDir();
      wf(dir, 'publish.yml', pub('release/v1', `        with:\n          attestations: ${value}\n`));
      expect(row(await coverage(dir, pkgService), 'deploy', 'attestation', 'app').status, value).toBe('missing');
    }
  });

  it('C2/I1/I2: where a hook comes from, what it formats, and file filters decide the pre-commit and CI rows', async () => {
    const RUFF_OLD = 'https://github.com/charliermarsh/ruff-pre-commit';
    const local = (body: string) => `repos:\n  - repo: local\n    hooks:\n      - id: x\n        name: x\n${body}`;
    // [config, format-lint hook, pre-commit secret scan, CI lint with `pre-commit run --all-files`]
    const cases: [string, string, string | undefined, string, string][] = [
      ['look-alike repo, id ruff', hookConfig('      - id: ruff\n', 'https://github.com/evil/ruff-pre-commit'), 'partial', 'missing', 'partial'],
      ['look-alike repo, id gitleaks', hookConfig('      - id: gitleaks\n', 'https://github.com/evil/x'), 'missing', 'partial', 'missing'],
      ['look-alike repo, id eslint', hookConfig('      - id: eslint\n', 'https://github.com/evil/x'), 'partial', 'missing', 'partial'],
      ['look-alike repo, entry ruff check', hookConfig('      - id: x\n        entry: ruff check\n', 'https://github.com/evil/x'), 'partial', 'missing', 'partial'],
      ['ruff-format only', hookConfig('      - id: ruff-format\n'), 'covered', 'missing', 'missing'],
      ['biome-format only', hookConfig('      - id: biome-format\n', 'https://github.com/biomejs/pre-commit'), 'covered', 'missing', 'missing'],
      ['files: ^$', hookConfig("      - id: ruff-check\n        files: '^$'\n"), 'partial', 'missing', 'partial'],
      ['exclude: .*', hookConfig("      - id: ruff-check\n        exclude: '.*'\n"), 'partial', 'missing', 'partial'],
      ['types: [jupyter]', hookConfig('      - id: ruff-check\n        types: [jupyter]\n'), 'partial', 'missing', 'partial'],
      ['types_or', hookConfig('      - id: ruff-check\n        types_or: [python]\n'), 'partial', 'missing', 'partial'],
      ['exclude_types', hookConfig('      - id: ruff-check\n        exclude_types: [markdown]\n'), 'partial', 'missing', 'partial'],
      ['top-level exclude', `exclude: '.*'\n${hookConfig('      - id: ruff-check\n')}`, 'partial', 'missing', 'partial'],
      ['top-level files', `files: '^$'\n${hookConfig('      - id: ruff-check\n')}`, 'partial', 'missing', 'partial'],
      ['stages: [manual]', hookConfig('      - id: ruff-check\n        stages: [manual]\n'), 'partial', 'missing', 'missing'],
      ['local language: fail', local('        entry: ruff is banned here\n        language: fail\n'), 'missing', 'missing', 'missing'],
      ['local language: pygrep', local('        entry: gitleaks\n        language: pygrep\n'), 'missing', 'missing', 'missing'],
      ['local language: system', local('        entry: ruff check\n        language: system\n'), 'covered', 'missing', 'covered'],
      ['meta with an entry', 'repos:\n  - repo: meta\n    hooks:\n      - id: identity\n        entry: ruff check\n', 'missing', 'missing', 'missing'],
      ['old gitleaks URL', hookConfig('      - id: gitleaks\n', 'https://github.com/zricethezav/gitleaks'), 'missing', 'covered', 'missing'],
      ['old ruff URL', hookConfig('      - id: ruff\n', RUFF_OLD), 'covered', 'missing', 'covered'],
      ['psf/black', hookConfig('      - id: black\n', 'https://github.com/psf/black'), 'covered', 'missing', 'missing'],
      ['ruff-check (control)', hookConfig('      - id: ruff-check\n'), 'covered', 'missing', 'covered'],
    ];
    for (const [name, config, fmt, secrets, ciLint] of cases) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', config);
      const hooks = await coverage(dir, py);
      expect(row(hooks, 'pre-commit', 'format-lint', 'app').status, `${name}: hook`).toBe(fmt);
      expect(row(hooks, 'pre-commit', 'secrets').status, `${name}: secrets`).toBe(secrets);
      wf(dir, 'ci.yml', PR(run('pre-commit run --all-files')));
      const withCi = await coverage(dir, py);
      expect(row(withCi, 'merge', 'lint', 'app').status, `${name}: CI lint`).toBe(ciLint);
      expect(row(withCi, 'merge', 'secrets').status, `${name}: CI secrets`).toBe('missing');
    }
    // a look-alike hook's why says so
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff\n', 'https://github.com/evil/ruff-pre-commit'));
    expect(row(await coverage(dir, py), 'pre-commit', 'format-lint', 'app').why)
      .toBe("The ruff check comes from a pre-commit hook repo pipegen doesn't know, so pipegen can't tell what it really runs.");
  });

  it('I1: `ruff format --check` and `biome format` in CI are formatting, not lint', async () => {
    for (const [cmd, lint] of [['ruff format --check .', 'missing'], ['biome format .', 'missing'], ['ruff check .', 'covered'], ['biome ci .', 'covered'], ['biome lint .', 'covered']]) {
      const dir = makeTempDir();
      wf(dir, 'ci.yml', PR(run(cmd as string)));
      expect(row(await coverage(dir), 'merge', 'lint', 'app').status, cmd).toBe(lint);
    }
  });

  it('I2: hooks carry into CI only when `pre-commit run` runs at the repo root', async () => {
    for (const steps of ['      - run: pre-commit run --all-files\n        working-directory: sub\n', run('cd sub && pre-commit run --all-files'), run('cd "$X" && pre-commit run --all-files')]) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
      writeIn(dir, 'sub/.pre-commit-config.yaml', 'repos: []\n');
      wf(dir, 'ci.yml', PR(steps));
      expect(row(await coverage(dir, py), 'merge', 'lint', 'app').status, steps).toBe('missing');
    }
  });

  it('I3: SKIP in the job, the step or inline makes "Git hooks re-run in CI" partial, and nothing carries over', async () => {
    for (const steps of [
      '      - uses: pre-commit/action@v3.0.1\n        env:\n          SKIP: ruff-check,gitleaks\n', run('SKIP=ruff-check pre-commit run --all-files'),
      '      - run: pre-commit run --all-files\n        env:\n          skip: ruff-check\n',
    ]) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
      wf(dir, 'ci.yml', PR(steps));
      const rows = await coverage(dir, py);
      const hooksCi = row(rows, 'merge', 'hooks-ci');
      expect(hooksCi.status, steps).toBe('partial');
      expect(hooksCi.why).toBe("The pre-commit check runs, but SKIP is set in this job, so some pre-commit hooks don't run here.");
      expect(row(rows, 'merge', 'lint', 'app').status, steps).toBe('missing');
    }
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
    wf(dir, 'ci.yml', `on:\n  pull_request:\njobs:\n  scan:\n    runs-on: x\n    env:\n      SKIP: ruff-check\n    steps:\n${run('pre-commit run --all-files')}`);
    expect(row(await coverage(dir, py), 'merge', 'hooks-ci').status).toBe('partial');
  });

  it('I4 (ruling U23): a script counted by name is lowered by its text (soft → partial, only no-ops → missing), never raised', async () => {
    for (const [cmd, scripts, status] of [
      ['npm run test:x', { 'test:x': 'echo ok' }, 'missing'],
      ['npm run test:x', { 'test:x': 'true' }, 'missing'],
      ['npm run test:x', { 'test:x': ':; exit 0' }, 'missing'],
      ['npm run test:x', { 'test:x': '' }, 'missing'],
      ['npm run test:x', { 'test:x': 'jest || true' }, 'partial'],
      ['npm test', { test: 'jest || true' }, 'partial'],
      ['npm test', { test: 'eslint . && jest --passWithNoTests' }, 'covered'],
      ['pnpm test', { test: 'vitest run; echo done' }, 'partial'],
      ['npm test', { test: 'node test.js' }, 'covered'], // an unknown runner keeps its by-name count (left-pad)
      ['npm test', { test: 'tape test/*.js' }, 'covered'],
      ['npm test', { other: 'jest' }, 'covered'], // no such script: by name, as S5
      ['npm test', { test: 'echo $(jest)' }, 'partial'],
    ] as [string, Record<string, string>, string][]) {
      const dir = makeTempDir();
      pkg(dir, scripts);
      wf(dir, 'ci.yml', PR(run(cmd)));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, `${cmd} ${JSON.stringify(scripts)}`).toBe(status);
    }
    const lint = makeTempDir();
    pkg(lint, { lint: 'eslint . --max-warnings=0 || echo failed' });
    wf(lint, 'ci.yml', PR(run('npm run lint')));
    expect(row(await coverage(lint), 'merge', 'lint', 'app').status).toBe('partial');
  });

  it('M2/M3/collect-only: modes that run no tests, commands after a top-level exit, and npm flags on by-name scripts', async () => {
    for (const [steps, scripts] of [
      [run('uv run tox r -- --collect-only'), null], [run('nox -- --co'), null], [run('uv run pytest --co'), null], [run('pytest --collect-only -q'), null],
      [run('python -m pytest --fixtures'), null], [run('jest --listTests'), null], [run('npx jest --showConfig'), null],
      [run('npm run ci'), { ci: 'jest --listTests' }], [run('npm run ci'), { ci: 'npm run test --workspace=none' }],
      [run('npm run test --workspace=none'), null], [run('npm test --workspaces'), null], [run('pnpm test --filter x'), null],
      ['      - run: |\n          exit 0\n          jest\n', null], [run('exit 0; jest'), null], [run('npm run ci'), { ci: 'exit 0; jest' }],
    ] as [string, Record<string, string> | null][]) {
      const dir = makeTempDir();
      if (scripts !== null) pkg(dir, scripts);
      wf(dir, 'ci.yml', PR(steps));
      expect(row(await coverage(dir, steps.includes('tox') || steps.includes('nox') || steps.includes('pytest') ? py : {}), 'merge', 'unit-tests', 'app').status, steps).toBe('missing');
    }
    // an exit that only runs on a condition, or inside a group or subshell, ends nothing
    for (const steps of [run('test -f x || exit 0; jest'), run('if [ -n "$X" ]; then exit 0; fi; jest'), run('(exit 0); jest'), run('jest; exit 0')]) {
      const dir = makeTempDir();
      wf(dir, 'ci.yml', PR(steps));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, steps).toBe('covered');
    }
  });

  it('M1: NPM_CONFIG_DRY_RUN in the env turns npm publish --provenance into a dry run', async () => {
    const rel = (env: string, steps: string) => `on:\n  release:\n    types: [published]\n${env}${job(steps)}`;
    for (const body of [
      rel('env:\n  NPM_CONFIG_DRY_RUN: "true"\n', run('npm publish --provenance')), rel('env:\n  npm_config_dry_run: "true"\n', run('npm publish --provenance')),
      rel('', run('npm_config_dry_run=true npm publish --provenance')), rel('', '      - run: npm publish --provenance\n        env:\n          NPM_CONFIG_DRY_RUN: "1"\n'),
    ]) {
      const dir = makeTempDir();
      wf(dir, 'release.yml', body);
      expect(row(await coverage(dir, { services: [svc('.', { scripts: ['test'] })] }), 'deploy', 'attestation', 'app').status, body).toBe('missing');
    }
  });
});
