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
    expect(row(rows, 'pre-commit', 'format-lint', 'app').status).toBe('missing'); // manual stage only: not a pre-commit hook
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
    const bad = '.github/workflows/a‮b.yml';
    writeIn(dir, bad, `on: push\n${job(run('gitleaks detect'))}`);
    const listed = listedWorkflow(bad);
    expect(row(await coverage(dir, { existingWorkflows: [listed] }), 'push', 'secrets').status).toBe('unknown'); // never a silent skip
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
