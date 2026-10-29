import { mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadToolSignatures, mapCoverage, type Coverage } from '../src/audit/coverage.js';
import { floorNeeds } from '../src/engine/needs.js';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import type { Capabilities, ExistingWorkflow, Layer, RepoProfile, Service } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';

// Ruling P33: a never-listed action (trivy-action, zizmor-action, …) is partial whatever its inputs. Older tests use
// trivy-action as the vehicle for the generic `with:` input rules (spellings, exit codes, crowded inputs); they turn
// the never-list off (`neverOff.on = true`) so the input rule they check stays visible. The P33 block tests the
// never-list itself, with it on.
const neverOff = vi.hoisted(() => ({ on: false }));
vi.mock('../src/engine/never-list.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/never-list.js')>();
  return { ...a, neverListed: (ref: unknown) => (neverOff.on ? null : a.neverListed(ref)) };
});
afterEach(() => {
  neverOff.on = false;
});

afterEach(cleanupRepos);

// A public repo whose plan allows attestations: keyless signing, so the deploy layer has sbom, signing and attestation.
const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: false,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};

const svc = (path: string, over: Partial<Service> = {}): Service => ({
  name: path === '.' ? 'app' : path.split('/').pop() as string, path, language: 'node', packageManager: 'npm', hasTests: true,
  envVars: [], dependsOn: [], scripts: ['test', 'lint'], frameworks: [], quality: emptyServiceQuality(), ...over,
});

/** A profile for `dir` the way readProject would build it: workflows and the hook manager read from disk. */
async function profileOf(dir: string, over: Partial<RepoProfile> = {}): Promise<RepoProfile> {
  return {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
    services: [svc('.')], terraformDirs: [], hasCompose: false,
    existingWorkflows: await readWorkflows(dir), precommit: readPrecommit(dir), repoFiles: emptyRepoFiles(), ...over,
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
    const rows = await coverage(dir, pyApp);
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
    expect(row(await coverage(dir2, pyApp), 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `python -m pytest`' });
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

  it('coverage: S2 a workflow path with a zero-width space or a tag character is skipped, never silently', async () => {
    for (const bad of ['.github/workflows/a\u200bb.yml', '.github/workflows/a\u{e0041}b.yml']) {
      const dir = makeTempDir();
      writeIn(dir, bad, `on: push\n${job(run('gitleaks detect'))}`);
      const rows = await coverage(dir, { existingWorkflows: [listedWorkflow(bad)] });
      expect(row(rows, 'push', 'secrets').status).toBe('unknown');
    }
  });

  it('coverage: S2 a local action path with an invisible character is not read', async () => {
    const action = 'runs:\n  using: composite\n  steps:\n    - run: gitleaks detect\n      shell: bash\n';
    const okDir = makeTempDir();
    wf(okDir, 'ci.yml', `on: push\n${job('      - uses: ./tools/scan\n')}`);
    writeIn(okDir, 'tools/scan/action.yml', action);
    expect(row(await coverage(okDir), 'push', 'secrets').status).toBe('covered'); // control: the plain path works
    for (const name of ['sc\u200ban', 'sc\u{e0041}an']) {
      const dir = makeTempDir();
      wf(dir, 'ci.yml', `on: push\n${job(`      - uses: ./tools/${name}\n`)}`);
      writeIn(dir, `tools/${name}/action.yml`, action);
      const r = row(await coverage(dir), 'push', 'secrets');
      expect(r.status).toBe('unknown');
      expect(r.why).toMatch(/couldn't read/);
    }
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
// P57 (C1): a tool counts only for services of its languages, so Python and Go tools are tested on Python and Go services
const pyApp = { services: [svc('.', { language: 'python', packageManager: 'uv', scripts: [] })] };
const goApp = { services: [svc('.', { language: 'go', packageManager: 'other', scripts: [] })] };
/** P57 (C1): the root service in the language of the command's runner (pytest/coverage → Python, go → Go, else Node). */
const langOver = (cmd: string): Partial<RepoProfile> => (/\bpytest\b|\bcoverage (?:run|report)\b|\btox\b|\bnox\b/.test(cmd) ? pyApp : /^go /.test(cmd) ? goApp : {});

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
      (await one(`${both}${job(`      - uses: ${uses}\n${withLines === '' ? '' : `        with:\n${withLines}`}`)}`, id === 'iac' || id === 'image-scan' ? 'merge' : 'push', id, over, service)).status;
    // Plan P Task 3 (PB3): trivy-action's default scan-type is image, so these are image scans, not dependency scans
    expect(await st('aquasecurity/trivy-action@0.28.0', '', 'image-scan', runnable, 'app')).toBe('partial');
    // Ruling P33 (final review I1): trivy-action is on pipegen's never-list (its tags were force-pushed to malicious
    // code), so even a step set up to fail is partial, never covered. This used to assert 'covered'.
    expect(await st('aquasecurity/trivy-action@0.28.0', "          exit-code: '1'\n", 'image-scan', runnable, 'app')).toBe('partial');
    expect(await st('aquasecurity/trivy-action@0.28.0', "          exit-code: '0'\n", 'image-scan', runnable, 'app')).toBe('partial');
    expect(await st('aquasecurity/trivy-action@0.28.0', '          exit-code: ${{ inputs.code }}\n', 'image-scan', runnable, 'app')).toBe('partial');
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
    const st = async (cmd: string, id = 'secrets', over: Partial<RepoProfile> = {}) => (await one(`${both}${job(run(cmd))}`, 'push', id, over, id === 'secrets' ? undefined : 'app')).status;
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
    expect(await st('uv run pytest', 'unit-tests', pyApp)).toBe('covered');
    expect(await st('pipx run pip-audit', 'deps', pyApp)).toBe('covered');
    expect(await st('python -m semgrep ci', 'sast')).toBe('covered');
    expect(await st('echo start && gitleaks detect')).toBe('covered'); // P54: the last && chain carries the step's status
    expect(await st('echo start && gitleaks detect; echo done')).toBe('partial'); // P53: not last, echo isn't on the && allowlist
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
    // Plan P Task 3 (PB3): trivy-action scans an image by default (image-scan, not deps)
    ['trivy-action Exit-Code: 1', `${both}${job("      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n          Exit-Code: '1'\n")}`, 'merge', 'image-scan', 'covered'],
    ['trivy-action exit-code empty', `${both}${job("      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n          exit-code: ''\n")}`, 'merge', 'image-scan', 'partial'],
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
    ['trivy-action exit-code 1, continue-on-error expression', `${both}${job("      - uses: aquasecurity/trivy-action@0.28.0\n        continue-on-error: \${{ github.event_name == 'push' }}\n        with:\n          exit-code: '1'\n")}`, 'merge', 'image-scan', 'partial'],
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
      neverOff.on = label.startsWith('trivy-action'); // the input rule, not the never-list (P33)
      // P57 (C1): Go and Python scanners are checked on a service of their language
      const lang = /^(gosec|govulncheck)/.test(label) ? 'go' : /^(bandit|pip-audit)/.test(label) ? 'python' : 'node';
      const over = lang === 'node' ? runnableTf : { ...runnableTf, services: [svc('.', { scripts: ['start'], language: lang })] };
      const r = await one(body, layer, id, over, id === 'secrets' || id === 'iac' ? undefined : 'app');
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
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    // Plan P Task 3 (PB3): trivy-action's default scan-type is image
    const st = async (lines: string) => (await one(`${both}${job(`      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n${lines}`)}`, 'merge', 'image-scan', runnable, 'app')).status;
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
    ['a multi-line if body still blocks', 'if true; then\n  gitleaks detect\nfi\necho next', 'partial'], // P53: an if body runs only under a condition
    ['a for body still blocks', 'for x in a; do gitleaks detect; done\necho next', 'covered'],
    // case arms: a pattern is not a command; the arm's body is
    ['a case arm body blocks', 'case "$E" in\n  push) gitleaks detect ;;\nesac\necho done', 'partial'], // P53: a case arm runs only under a condition
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
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    // exit-code has 9 letters: 2^9 case spellings; each sets the failing value '1'
    const variants = (n: number) => Array.from({ length: n }, (_, i) => Array.from('exit-code', (ch, b) => ((i >> b) & 1 ? ch.toUpperCase() : ch)).join(''));
    // Plan P Task 3 (PB3): trivy-action's default scan-type is image, and the entry is trivy-image
    expect((await one(trivy(variants(8).map((k) => `${k}: '1'`)), 'merge', 'image-scan', runnable, 'app')).status).toBe('covered');
    const r = await one(trivy(variants(9).map((k) => `${k}: '1'`)), 'merge', 'image-scan', runnable, 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toBe('The trivy-image check runs, but its step sets more inputs than pipegen reads, so pipegen can\'t tell whether it blocks anything.');
  });

  it('coverage: round 4: a step with more inputs than pipegen reads → partial, never covered', async () => {
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    const filler = (n: number) => spellings(n).map((k) => `${k}: x`);
    expect((await one(trivy(["exit-code: '1'", ...filler(255)]), 'merge', 'image-scan', runnable, 'app')).status).toBe('covered');
    const r = await one(trivy(["exit-code: '1'", ...filler(256)]), 'merge', 'image-scan', runnable, 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/sets more inputs than pipegen reads/);
  });

  it('coverage: round 4: a 30,000-key with: map is read in linear time', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', trivy(["exit-code: '1'", ...spellings(30_000).map((k) => `${k}: 1`)]));
    const t = performance.now();
    const p = await profileOf(dir, runnable);
    expect(p.existingWorkflows).toHaveLength(1); // under the 1 MB read limit, so it really is read
    const r = row(await mapCoverage(p, floorNeeds(p, caps), dir), 'merge', 'image-scan', 'app');
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
    // Plan P Task 3 (PB3): trivy is split by subcommand (trivy-image, trivy-fs, trivy-config, …)
    for (const id of ['gitleaks', 'trufflehog', 'semgrep', 'codeql', 'snyk', 'trivy-image', 'trivy-fs', 'trivy-config', 'grype', 'osv-scanner', 'npm-audit', 'zap', 'eslint', 'jest', 'vitest', 'cosign', 'syft', 'attest-build-provenance']) {
      expect(ids).toContain(id);
    }
    expect(new Set(ids).size).toBe(ids.length);
    for (const t of list) expect((t.actions?.length ?? 0) + (t.commands?.length ?? 0) + (t.reusableWorkflows?.length ?? 0)).toBeGreaterThan(0);
  });

  it('signatures: unknown keys, unknown categories and bad patterns are refused', () => {
    const dir = makeTempDir();
    const load = (yaml: string) => {
      writeIn(dir, 'sig.yml', yaml);
      return () => loadToolSignatures(join(dir, 'sig.yml'));
    };
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: [a]\n')()).toHaveLength(1);
    // P57 (C1): every signature names the languages it checks; `any` stands alone
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    commands: [a]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any, node]\n    commands: [a]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [cobol]\n    commands: [a]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [lint]\n    languages: [node, unknown]\n    commands: [a]\n')()).toHaveLength(1);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: [a]\n    extra: 1\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [nope]\n    languages: [any]\n    commands: [a]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    actions: [noslash]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: ["a(b|c)*"]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: [a]\n    commandFails: flag\n')).toThrow(/not valid/); // flag needs failFlags
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    actions: [o/a]\n    actionFails: input\n')).toThrow(/not valid/); // input needs failInputs
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: [a]\n    softFlags: [exit-zero]\n')).toThrow(/not valid/); // not a flag
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: [a]\n    partialWhy: lower case and no stop\n')).toThrow(/not valid/);
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    actions: [o/a*/b]\n')).toThrow(/not valid/); // * only on the last part
    expect(load('tools:\n  - id: a\n    categories: [secrets]\n    languages: [any]\n    commands: [a]\n  - id: a\n    categories: [sast]\n    languages: [any]\n    commands: [b]\n')).toThrow(/not valid/);
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
    const rows = await coverage(dir, pyApp);
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
      expect(row(await coverage(dir, pyApp), 'push', 'unit-tests', 'app'), cmd).toMatchObject({ status: 'covered', by });
    }
  });

  it('python runners (adversarial): uv run wrapping something that is not a test runner, and tox or nox runs that pick other envs on the command line → missing', async () => {
    for (const steps of [
      run('uv run --group dev python scripts/build.py'), run('uv run --with ruff python -c pass'), run('uv run --with pytest python -c pass'),
      run('uv run --some-new-flag pytest'), run('uv run -qx pytest'), run('tox run -e typing'), run('tox -e py312'), run('tox list'), run('tox run --notest'),
      run('tox -re lint'), run('tox --override testenv.commands=true'), run('nox -s lint'), run('nox --list'), run('nox -k lint'),
    ]) {
      const dir = makeTempDir();
      ci(dir, steps);
      expect(row(await coverage(dir, pyApp), 'push', 'unit-tests', 'app').status, steps).toBe('missing');
    }
  });

  it('python runners (adversarial): a TOX… or NOX… variable that may pick other envs → partial, never covered (Plan U final review I2)', async () => {
    for (const steps of [
      run('TOXENV=lint tox'), '      - run: tox run\n        env:\n          TOX_ENV: lint\n', '      - run: tox run\n        env:\n          TOXENV: lint\n',
      '      - run: nox\n        env:\n          NOXSESSION: lint\n', run('echo "TOXENV=lint" >> "$GITHUB_ENV"') + run('tox run'),
    ]) {
      const dir = makeTempDir();
      ci(dir, steps);
      expect(row(await coverage(dir, pyApp), 'push', 'unit-tests', 'app').status, steps).toBe('partial');
    }
    // an env set for the whole job or workflow picks the envs too
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}env:\n  TOX_ENV: lint\n${job(run('tox run'))}`);
    expect(row(await coverage(dir, pyApp), 'push', 'unit-tests', 'app').status).toBe('partial');
    const dir2 = makeTempDir();
    ci(dir2, run('tox run'), '    env:\n      TOX_ENV: lint\n');
    expect(row(await coverage(dir2, pyApp), 'push', 'unit-tests', 'app').status).toBe('partial');
  });
});

const RUFF_REPO = 'https://github.com/astral-sh/ruff-pre-commit';
const hookConfig = (hooks: string, repo = RUFF_REPO) => `repos:\n  - repo: ${repo}\n    rev: v0.16.0\n    hooks:\n${hooks}`;
const FLASK_PRECOMMIT = 'uv run --locked --no-default-groups --group pre-commit pre-commit run --show-diff-on-failure --color=always --all-files';

describe('mapCoverage (P55 batch B: docker compose and Dockerfile RUN)', () => {
  const web = svc('backend', { scripts: ['start'], frameworks: ['express'], language: 'python', packageManager: 'uv' });
  const root = svc('.', { name: 'app', scripts: ['start'], frameworks: ['express'], language: 'python', packageManager: 'uv' });
  const COMPOSE = 'services:\n  web:\n    build: ./backend\n  tests:\n    build:\n      context: .\n      dockerfile: backend/Dockerfile\n      target: test\n  db:\n    image: postgres:18\n';
  const DOCKERFILE = 'FROM python:3.14 AS base\nWORKDIR /app\nCOPY ./backend /app\nFROM base AS test\nRUN pytest\nFROM base AS final\nRUN echo done\n';
  const statusOf = async (files: Record<string, string>, steps: string, id = 'unit-tests', service = 'backend', services = [web, root], layer: Layer = 'merge') => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    const rows = await coverage(dir, { services });
    const r = row(rows, layer, id, service);
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };

  it('docker compose build (and docker-compose, -f, up --build) is a partial image build; a dry run or a plain up is not', async () => {
    const image = (steps: string) => statusOf({ 'compose.yml': COMPOSE }, steps, 'image-build');
    // P57 (C3): --project-directory moves where compose reads its files, but the build still runs (what it runs is unknown)
    for (const cmd of ['docker compose build', 'docker-compose build', 'docker compose -f compose.yml build web', 'docker compose up --build -d', 'docker compose --project-directory x build']) {
      expect(await image(run(cmd)), cmd).toBe('partial docker-compose-build');
    }
    for (const cmd of ['docker compose --dry-run build', 'docker compose up -d', 'docker compose build --dry-run']) {
      expect(await image(run(cmd)), cmd).toBe('missing');
    }
  });

  it('docker compose run|exec <service> <command> counts for the folder the service builds from', async () => {
    const t = (cmd: string, files: Record<string, string> = { 'compose.yml': COMPOSE }) => statusOf(files, run(cmd));
    expect(await t('docker compose run --rm web pytest')).toBe('covered your own `pytest`');
    expect(await t('docker compose -f compose.yml run --rm -T -e A=b web pytest -q')).toBe('covered your own `pytest`');
    expect(await t('docker compose exec -T web pytest')).toBe('covered your own `pytest`');
    expect(await t('docker-compose run web pytest')).toBe('covered your own `pytest`');
    // the root service is not the one that is tested
    expect(await statusOf({ 'compose.yml': COMPOSE }, run('docker compose run --rm web pytest'), 'unit-tests', 'app')).toBe('missing');
    // look-alikes: the failure doesn't fail the step, another command or folder, an unknown flag, a service that isn't built here
    expect(await t('docker compose run --rm web pytest || true')).toBe('partial your own `pytest`');
    for (const cmd of ['docker compose run --rm --entrypoint sh web pytest', 'docker compose run --rm -w /x web pytest', 'docker compose run --rm --weird web pytest', 'docker compose run web', 'docker compose --dry-run run web pytest']) {
      expect(await t(cmd), cmd).toBe('missing');
    }
    expect(await t('docker compose run --rm db pytest')).toMatch(/^unknown/); // a ready-made image: pipegen can't tell which service it checks
    expect(await t('docker compose run --rm nope pytest')).toMatch(/^unknown/);
    expect(await t('docker compose run --rm web pytest', {})).toBe('missing'); // no compose file: the runner fails
    // a script file is read from the service's build folder (the image holds the repo's copy); one that isn't there is unknown
    expect(await t('docker compose run --rm web bash scripts/t.sh', { 'compose.yml': COMPOSE, 'backend/scripts/t.sh': 'pytest\n' })).toBe('covered your own `scripts/t.sh`');
    expect(await t('docker compose run --rm web bash scripts/t.sh', { 'compose.yml': COMPOSE, 'backend/scripts/t.sh': 'echo hi\n' })).toBe('missing');
    expect(await t('docker compose run --rm web bash scripts/t.sh')).toMatch(/^unknown/);
  });

  it('compose run places the command in the image\'s last WORKDIR (the fastapi shape: context ".", WORKDIR /app/backend, COPY ./backend/scripts)', async () => {
    const compose = 'services:\n  backend:\n    build:\n      context: .\n      dockerfile: backend/Dockerfile\n';
    const dockerfile = 'FROM python:3.14\nWORKDIR /app/\nCOPY ./backend/scripts /app/backend/scripts\nCOPY ./backend/pyproject.toml ./backend/alembic.ini /app/backend/\nWORKDIR /app/backend/\n';
    const files = { 'compose.yml': compose, 'backend/Dockerfile': dockerfile, 'backend/pyproject.toml': '[project]\nname = "a"\n', 'backend/alembic.ini': '[alembic]\n', 'backend/scripts/t.sh': 'pytest\n', 'scripts/other.sh': 'pytest\n' };
    const t = (cmd: string, f: Record<string, string> = files) => statusOf(f, run(cmd));
    expect(await t('docker compose run --rm backend bash scripts/t.sh')).toBe('covered your own `scripts/t.sh`');
    expect(await t('docker compose run --rm backend pytest')).toBe('covered your own `pytest`');
    // the script that is at the repo root is not the one in the image's working folder
    expect(await t('docker compose run --rm backend bash scripts/other.sh')).toMatch(/^unknown/);
  });

  it('a RUN in a Dockerfile `docker build` builds counts under the same rules (stages, folders, conditions)', async () => {
    const files = (dockerfile: string, extra: Record<string, string> = {}) => ({ 'backend/Dockerfile': dockerfile, 'backend/app.py': 'x = 1\n', ...extra });
    const build = (flags = '-f backend/Dockerfile .') => run(`docker build ${flags}`);
    const st = (dockerfile: string, steps = build(), extra: Record<string, string> = {}) => statusOf(files(dockerfile, extra), steps);
    const single = 'FROM python:3.14\nWORKDIR /app\nCOPY ./backend /app\nRUN pytest\n';
    expect(await st(single)).toBe('covered your own `pytest`');
    expect(await st('FROM python:3.14\nWORKDIR /app\nCOPY . /app\nRUN pytest\n', run('docker build backend'))).toBe('covered your own `pytest`'); // the context is backend/
    expect(await st('FROM python:3.14\nWORKDIR /app\nCOPY . .\nRUN ["pytest", "-q"]\n', run('docker build backend'))).toBe('covered your own `pytest`');
    // only the stages the final stage needs are built
    expect(await st(DOCKERFILE)).toBe('missing');
    expect(await st(DOCKERFILE, build('--target test -f backend/Dockerfile .'))).toBe('covered your own `pytest`');
    expect(await st(`${DOCKERFILE}COPY --from=test /app /out\n`)).toBe('covered your own `pytest`');
    expect(await st('FROM python:3.14 AS test\nWORKDIR /app\nCOPY ./backend /app\nRUN pytest\nFROM scratch\nCOPY --from=ghcr.io/x/y /a /b\n')).toBe('missing');
    expect(await st(DOCKERFILE, build('--target nope -f backend/Dockerfile .'))).toMatch(/^unknown/);
    // a RUN that can't fail the build, or runs under a condition
    for (const runLine of ['RUN pytest || true', 'RUN pytest; echo ok', 'RUN if [ -n "$X" ]; then pytest; fi']) {
      expect(await st(`FROM python:3.14\nWORKDIR /app\nCOPY ./backend /app\n${runLine}\n`), runLine).toBe('partial your own `pytest`');
    }
    // a Dockerfile pipegen can't read the way the builder does is unknown, never covered
    for (const dockerfile of ['FROM x\nRUN <<EOF\npytest\nEOF\n', 'FROM x\nSHELL ["/bin/bash", "-c"]\nRUN pytest\n', '# escape=`\nFROM x\nRUN pytest\n']) {
      expect(await st(dockerfile), dockerfile).toMatch(/^unknown/);
    }
    // a command that doesn't name one Dockerfile, a check run, or a build the step can't fail
    for (const steps of [run('docker build --weird -f backend/Dockerfile .'), run('docker build --check -f backend/Dockerfile .'), run('docker build -f backend/Dockerfile'), run('docker build -f "$F" .'),
      run('docker build -f backend/Dockerfile . || true'), '      - run: docker build -f backend/Dockerfile .\n        continue-on-error: true\n']) {
      expect(await st(single, steps), steps).not.toBe('covered your own `pytest`');
    }
    expect(await st(single, run('docker build -f backend/Dockerfile . || true'))).toBe('partial your own `pytest`');
    expect(await st(single, "      - run: docker build -f backend/Dockerfile .\n        if: github.actor != 'bot'\n")).toBe('partial your own `pytest`');
    // no Dockerfile at that path: the build fails, nothing runs
    expect(await st(single, run('docker build -f backend/Missing.Dockerfile .'))).toBe('missing');
    // a Dockerfile that is a symbolic link is not read: unknown
    const dir = makeTempDir();
    const outside = makeTempDir();
    writeIn(outside, 'Dockerfile', single);
    mkdirSync(join(dir, 'backend'), { recursive: true });
    symlinkSync(join(outside, 'Dockerfile'), join(dir, 'backend/Dockerfile'));
    ci(dir, build());
    const linked = row(await coverage(dir, { services: [web, root] }), 'merge', 'unit-tests', 'backend');
    expect(linked.status).toBe('unknown');
  });

  it('a RUN counts through docker/build-push-action (file, context, target) and docker compose build, with the compose service\'s folder and target', async () => {
    const act = (w: string) => `      - uses: docker/build-push-action@v6\n        with:\n${w}`;
    const f = { 'backend/Dockerfile': DOCKERFILE, 'backend/app.py': 'x = 1\n' };
    expect(await statusOf(f, act('          file: backend/Dockerfile\n          target: test\n'))).toBe('covered your own `pytest`');
    expect(await statusOf({ ...f, 'backend/Dockerfile': DOCKERFILE.replace('COPY ./backend /app', 'COPY . /app') }, act('          context: ./backend\n          target: test\n'))).toBe('covered your own `pytest`');
    for (const w of ['          file: backend/Dockerfile\n', '          file: backend/Dockerfile\n          target: ${{ matrix.t }}\n', '          file: backend/Dockerfile\n          target: test\n          call: check\n', '          context: .\n          target: test\n']) {
      expect(await statusOf(f, act(w)), w).not.toBe('covered your own `pytest`');
    }
    // compose build: the `tests` service builds backend/Dockerfile up to its `test` target; `web` builds the final stage
    const both = { ...f, 'compose.yml': COMPOSE };
    expect(await statusOf(both, run('docker compose build'))).toBe('covered your own `pytest`');
    expect(await statusOf(both, run('docker compose build tests'))).toBe('covered your own `pytest`');
    expect(await statusOf(both, run('docker compose build web'))).toBe('missing'); // only the stages `web` needs
    expect(await statusOf(both, run('docker compose build db'))).toBe('missing');
    expect(await statusOf({ ...both, 'compose.yml': 'services:\n  tests:\n    build: ${CTX}\n' }, run('docker compose build'))).toMatch(/^unknown/);
  });

  it('a script run in the folder a RUN works in is read there (bun run build in WORKDIR /app/frontend type-checks the frontend)', async () => {
    const fe = svc('frontend', { quality: { ...emptyServiceQuality(), tsconfig: true, versions: { typescript: '5.9.2' } } });
    const files = {
      'frontend/package.json': JSON.stringify({ name: 'frontend', scripts: { build: 'tsc -p tsconfig.build.json && vite build' } }), 'frontend/src/main.ts': 'x\n',
      'backend/Dockerfile': 'FROM oven/bun:1 AS build\nWORKDIR /app\nCOPY frontend/package.json /app/frontend/\nWORKDIR /app/frontend\nCOPY ./frontend /app/frontend\nRUN bun run build\nFROM python:3.14\nCOPY --from=build /app/dist /dist\n',
    };
    const status = (steps: string) => statusOf(files, steps, 'type-check', 'frontend', [web, fe]);
    expect(await status(run('docker build -f backend/Dockerfile .'))).toBe('covered your own `bun run build`');
    // a WORKDIR no COPY maps to a repo folder is a folder pipegen can't place: unknown
    expect(await statusOf({ ...files, 'backend/Dockerfile': 'FROM oven/bun:1\nWORKDIR /somewhere\nRUN bun run build\n' }, run('docker build -f backend/Dockerfile .'), 'type-check', 'frontend', [web, fe])).toMatch(/^unknown/);
  });
});

describe('mapCoverage (P55 batch B: XO)', () => {
  const lintStatus = async (steps: string, scripts: Record<string, string> = {}) => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', JSON.stringify({ name: 'app', scripts }));
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(steps)}`);
    const rows = await coverage(dir);
    return ['push', 'merge'].map((l) => { const r = row(rows, l as Layer, 'lint', 'app'); return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`; });
  };

  it('xo in a step or in the service\'s test script covers lint (ky shape: `xo && npm run build && tsc && ava`)', async () => {
    expect(await lintStatus(run('npx xo'))).toEqual(['covered xo', 'covered xo']);
    expect(await lintStatus(run('npm test'), { test: 'xo && npm run build && tsc --project tsconfig.test.json && ava' })).toEqual(['covered your own `npm test`', 'covered your own `npm test`']);
  });

  it('xo that can\'t fail the build, fixes instead, or only prints is not covered', async () => {
    for (const cmd of ['xo || true', 'xo --fix', 'xo --stdin < a.js', 'xo --print-config a.js', 'xo --version']) {
      const [push] = await lintStatus(run(cmd));
      expect(push, cmd).not.toBe('covered xo');
    }
    expect((await lintStatus(run('xo || true')))[0]).toBe('partial xo');
    expect((await lintStatus(run('npm test'), { test: 'xo; ava' }))[0]).toBe('partial your own `npm test`');
    expect((await lintStatus('      - run: xo\n        continue-on-error: true\n'))[0]).toBe('partial xo');
  });
});

describe('mapCoverage (P55 batch B: prek)', () => {
  const lintOf = async (config: string, steps: string, extraWf = '') => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', config);
    wf(dir, 'ci.yml', `on:\n  pull_request:\n${job(steps, extraWf)}`);
    return coverage(dir, pyApp);
  };
  const cfg = hookConfig('      - id: ruff-check\n');
  const CHANGED = 'uv run prek run --from-ref origin/${GITHUB_BASE_REF} --to-ref HEAD --show-diff-on-failure';

  it('prek run --all-files counts like pre-commit: hooks-ci covered by prek, the hooks\' lint carried', async () => {
    const rows = await lintOf(cfg, run('uv run prek run --all-files'));
    expect(row(rows, 'merge', 'hooks-ci')).toMatchObject({ status: 'covered', by: 'prek' });
    expect(row(rows, 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'ruff' });
  });

  it('j178/prek-action: --all-files by default; install-only, a hook id or a moved folder carry nothing', async () => {
    const act = (w = '') => `      - uses: j178/prek-action@v1\n${w === '' ? '' : `        with:\n${w}`}`;
    expect(row(await lintOf(cfg, act()), 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'ruff' });
    expect(row(await lintOf(cfg, act('          extra-args: --all-files\n')), 'merge', 'lint', 'app').status).toBe('covered');
    for (const w of ['          install-only: true\n', '          extra-args: ruff-check --all-files\n', '          working-directory: sub\n',
      '          extra-args: --all-files\n          extra_args: ruff-check\n', '          extra-args: ${{ inputs.a }}\n']) {
      expect(row(await lintOf(cfg, act(w)), 'merge', 'lint', 'app').status, w).toBe('missing');
    }
    // install-only: the action runs no hooks, so it is not the hooks-in-CI check either
    expect(row(await lintOf(cfg, act('          install-only: true\n')), 'merge', 'hooks-ci').status).toBe('missing');
  });

  it('a run over the files between two refs is partial ("changed"), for prek and pre-commit; no refs and no --all-files carries nothing', async () => {
    for (const cmd of [CHANGED, 'pre-commit run --from-ref origin/main --to-ref HEAD', 'prek run -s origin/main -o HEAD']) {
      const rows = await lintOf(cfg, run(cmd));
      const lint = row(rows, 'merge', 'lint', 'app');
      expect(lint, cmd).toMatchObject({ status: 'partial', by: 'ruff' });
      expect(lint.why).toMatch(/only on the files that changed between two commits/);
      expect(row(rows, 'merge', 'hooks-ci').status).toBe('covered');
    }
    // P59 (2): `--files a.py` is part of the repo (partial), tested with the other part-of-repo flags
    for (const cmd of ['prek run', 'prek run --from-ref origin/main', 'prek run --all-files --from-ref a --to-ref b', 'prek run ruff-check --from-ref a --to-ref b']) {
      expect(row(await lintOf(cfg, run(cmd)), 'merge', 'lint', 'app').status, cmd).toBe('missing');
    }
    const act = "      - uses: j178/prek-action@v1\n        with:\n          extra-args: --from-ref origin/main --to-ref HEAD\n";
    expect(row(await lintOf(cfg, act), 'merge', 'lint', 'app')).toMatchObject({ status: 'partial', by: 'ruff' });
  });

  it('SKIP in the job lowers the prek hooks it names (P57 C4), a conditional or soft run stays partial', async () => {
    expect(row(await lintOf(cfg, run('SKIP=ruff-check prek run --all-files')), 'merge', 'lint', 'app').status).toBe('partial');
    expect(row(await lintOf(cfg, run('prek run --all-files || true')), 'merge', 'lint', 'app').status).toBe('partial');
    expect(row(await lintOf(cfg, '      - run: prek run --all-files\n        if: github.actor != \'bot\'\n'), 'merge', 'lint', 'app').status).toBe('partial');
    expect(row(await lintOf(cfg, '      - run: prek run --all-files\n        continue-on-error: true\n'), 'merge', 'lint', 'app').status).toBe('partial');
  });

  it('continue-on-error undone by a later `exit 1` step on the same id counts as blocking; look-alikes do not', async () => {
    const step = (coe = 'true') => `      - id: pc\n        run: prek run --all-files\n        continue-on-error: ${coe}\n`;
    const later = (cond: string, runText = 'exit 1', extra = '') => `      - name: fail\n        if: ${cond}\n        run: ${runText}\n${extra}`;
    const lint = async (steps: string) => row(await lintOf(cfg, steps), 'merge', 'lint', 'app').status;
    expect(await lint(step() + later("steps.pc.outcome == 'failure'"))).toBe('covered');
    expect(await lint(step() + later("${{ steps.pc.outcome == 'failure' }}"))).toBe('covered');
    expect(await lint(step() + later("steps.pc.outcome != 'success'", '"false"'))).toBe('covered');
    // without the later step, or with a look-alike one, the run can't fail the job
    expect(await lint(step())).toBe('partial');
    for (const l of [
      later("steps.pc.outcome == 'success'"), later("steps.other.outcome == 'failure'"), later("steps.pc.outcome == 'failure' && github.actor != 'x'"),
      later("steps.pc.outcome == 'failure'", 'exit 0'), later("steps.pc.outcome == 'failure'", 'echo bad'), later("steps.pc.conclusion == 'failure'"),
      later("steps.pc.outcome == 'failure'", 'exit 1', '        continue-on-error: true\n'), later("steps.pc.outcome == 'failure'", 'exit 1', '        shell: bash {0}\n'),
    ]) expect(await lint(step() + l), l).toBe('partial');
    // the later step must come after the step it names
    expect(await lint(later("steps.pc.outcome == 'failure'") + step())).toBe('partial');
    // 'changed' stays partial under the rescue, with its own reason
    const changed = `      - id: pc\n        run: ${CHANGED}\n        continue-on-error: true\n` + later("steps.pc.outcome == 'failure'");
    const r = row(await lintOf(cfg, changed), 'merge', 'lint', 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/only on the files that changed/);
  });
});

describe('mapCoverage (Task 5, item 3: pre-commit hook contents)', () => {
  it('pre-commit hooks: ruff-check and ruff-format hooks → the format and lint hook is covered', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n      - id: ruff-format\n'));
    const rows = await coverage(dir, pyApp);
    expect(row(rows, 'pre-commit', 'format-lint', 'app')).toMatchObject({ status: 'covered', by: 'ruff', where: '.pre-commit-config.yaml' });
    expect(row(rows, 'pre-commit', 'hooks')).toMatchObject({ status: 'covered', by: 'pre-commit' });
  });

  it('pre-commit hooks: CI running `pre-commit run --all-files` (also through uv run) covers lint with the hooks\' tools (flask shape)', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n      - id: ruff-format\n'));
    wf(dir, 'pre-commit.yaml', `on:\n  pull_request:\n  push:\n    branches: [main, stable]\n${job(run(FLASK_PRECOMMIT))}`);
    const rows = await coverage(dir, pyApp);
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
    expect(row(await coverage(dir2, pyApp), 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'ruff' });
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
      const rows = await coverage(dir, pyApp);
      expect(row(rows, 'pre-commit', 'format-lint', 'app').status, config).toBe(expected);
      expect(row(rows, 'pre-commit', 'secrets').status, config).toBe('missing');
    }
  });

  it('pre-commit hooks (adversarial): CI runs that check no files, one hook, another stage or skip hooks don\'t cover lint', async () => {
    const config = hookConfig('      - id: ruff-check\n');
    for (const steps of [
      run('pre-commit run'), run('pre-commit run ruff-check --all-files'), run('pre-commit run --hook-stage manual --all-files'),
      run('pre-commit run -c other.yaml --all-files'), // P59 (2): --files a.py is partial now, tested apart
      "      - uses: pre-commit/action@v3.0.1\n        with:\n          extra_args: ruff-check --all-files\n",
      "      - uses: pre-commit/action@v3.0.1\n        with:\n          extra_args: ${{ inputs.args }}\n",
    ]) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', config);
      ci(dir, steps);
      expect(row(await coverage(dir, pyApp), 'merge', 'lint', 'app').status, steps).toBe('missing');
    }
    // P57 (C4): SKIP naming the hook leaves it partial (never covered); it was dropped before
    for (const steps of [run('SKIP=ruff-check pre-commit run --all-files'), '      - run: pre-commit run --all-files\n        env:\n          SKIP: ruff-check\n',
      run('echo "SKIP=ruff-check" >> "$GITHUB_ENV"') + run('pre-commit run --all-files')]) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', config);
      ci(dir, steps);
      expect(row(await coverage(dir, pyApp), 'merge', 'lint', 'app').status, steps).toBe('partial');
    }
  });

  it('pre-commit hooks (adversarial): a secret-scan hook run in CI is not a CI secret scan (it scans staged changes); soft hook args → partial', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: gitleaks\n', 'https://github.com/gitleaks/gitleaks'));
    ci(dir, run('pre-commit run --all-files'));
    const rows = await coverage(dir, pyApp);
    expect(row(rows, 'pre-commit', 'secrets')).toMatchObject({ status: 'covered', by: 'gitleaks' });
    expect(row(rows, 'merge', 'secrets').status).toBe('missing');
    const dir2 = makeTempDir();
    writeIn(dir2, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n        args: [--exit-zero]\n'));
    ci(dir2, run('pre-commit run --all-files'));
    expect(row(await coverage(dir2, pyApp), 'merge', 'lint', 'app').status).toBe('partial');
  });
});

describe('mapCoverage (Task 5, item 4: package publishing at the deploy layer)', () => {
  const pkgService = { services: [svc('.', { scripts: ['test'] })] };
  const pyPkg = { services: [svc('.', { scripts: ['test'], language: 'python', packageManager: 'uv' })] }; // P57 (C1): PyPI publishes a Python package
  const tagPush = 'on:\n  push:\n    tags: [\'*\']\n';

  it('deploy: pypa/gh-action-pypi-publish with trusted publishing → attestation covered (flask shape)', async () => {
    const dir = makeTempDir();
    wf(dir, 'publish.yaml', `${tagPush}${job('      - uses: pypa/gh-action-pypi-publish@v1.14.2\n        with:\n          packages-dir: "dist/"\n', `    permissions:\n      ${'id-' + 'token'}: write\n`)}`); // built at runtime (secret-literal guard)
    expect(row(await coverage(dir, pyPkg), 'deploy', 'attestation', 'app')).toMatchObject({ status: 'covered', by: 'pypi-publish' });
  });

  it('deploy (adversarial): pypi-publish with a password, attestations off or another index makes no attestation → missing', async () => {
    for (const w of [`${'pass' + 'word'}: \${{ secrets.${'PYPI_' + 'TOKEN'} }}`, 'attestations: false', 'Attestations: "false"', 'attestations: ${{ inputs.attest }}', 'repository-url: https://pypi.example.test/legacy/', 'repository_url: https://pypi.example.test/legacy/']) {
      const dir = makeTempDir();
      wf(dir, 'publish.yaml', `${tagPush}${job(`      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          ${w}\n`)}`);
      expect(row(await coverage(dir, pyPkg), 'deploy', 'attestation', 'app').status, w).toBe('missing');
    }
    const ok = makeTempDir();
    wf(ok, 'publish.yaml', `${tagPush}${job('      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          repository-url: https://test.pypi.org/legacy/\n')}`);
    expect(row(await coverage(ok, pyPkg), 'deploy', 'attestation', 'app').status).toBe('covered');
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
    const pkgService = { services: [svc('.', { scripts: ['test'], language: 'python', packageManager: 'uv' })] };
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
      const hooks = await coverage(dir, name.startsWith('biome') ? {} : py); // P57 (C1): biome formats Node code
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
      expect(row(await coverage(dir, (cmd as string).startsWith('ruff') ? py : {}), 'merge', 'lint', 'app').status, cmd).toBe(lint);
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

  it('I3: SKIP in the job, the step or inline makes "Git hooks re-run in CI" partial; P57 (C4): the hooks it names are partial', async () => {
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
      expect(hooksCi.why).toBe("The pre-commit check runs, but SKIP or PREK_SKIP is set in this job, so some pre-commit hooks don't run here.");
      expect(row(rows, 'merge', 'lint', 'app').status, steps).toBe('partial');
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
      ['npm test', { test: 'eslint . && jest --passWithNoTests' }, 'covered'], // P54: the script's last && chain
      ['npm test', { test: 'eslint . && jest --passWithNoTests; echo ok' }, 'partial'], // P53: not last
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
    // an exit that only runs on a condition, or inside a group or subshell, ends nothing; P53: what follows it runs only
    // under that condition, so it is partial
    for (const steps of [run('test -f x || exit 0; jest'), run('if [ -n "$X" ]; then exit 0; fi; jest'), run('(exit 0); jest')]) {
      const dir = makeTempDir();
      wf(dir, 'ci.yml', PR(steps));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, steps).toBe('partial');
    }
    const after = makeTempDir();
    wf(after, 'ci.yml', PR(run('jest; exit 0')));
    expect(row(await coverage(after), 'merge', 'unit-tests', 'app').status).toBe('covered');
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

// ---------- Task 5 fix round 2: the re-review's probes (task-5-rereview-1.md N1–N5) ----------

describe('mapCoverage (Task 5 fix round 2)', () => {
  const py = { services: [svc('.', { language: 'python', packageManager: 'uv', scripts: [] })] };
  const PR = (steps: string) => `on:\n  pull_request:\n${job(steps)}`;

  it('N1/N3 (U23): a by-name script that runs nothing is missing; one whose real runs all can\'t fail it is partial', async () => {
    for (const [cmd, scripts, status] of [
      // (d) an own-script call that does nothing, followed
      ['npm test', { test: 'npm run a', a: 'echo ok' }, 'missing'],
      ['npm test', { test: 'npm run test:unit', 'test:unit': 'echo ok' }, 'missing'],
      ['npm test', { test: 'yarn test:unit', 'test:unit': 'true' }, 'missing'],
      ['npm test', { test: 'npm run a', a: 'npm run b', b: 'npm run c', c: ':' }, 'missing'],
      ['npm test', { test: 'npm run a', a: 'npm run test' }, 'missing'], // a cycle does nothing
      // (b) dead code
      ['npm test', { test: 'exit 0; jest' }, 'missing'],
      ['npm test', { test: 'true || jest' }, 'missing'],
      ['npm test', { test: 'echo skip || { jest; }' }, 'missing'],
      ['npm test', { test: 'false && jest' }, 'missing'],
      // (c) a mode that runs no tests
      ['npm test', { test: 'jest --listTests' }, 'missing'],
      ['npm test', { test: 'pytest --co' }, 'missing'],
      ['npm test', { test: 'vitest --version' }, 'missing'],
      // cross-env is a wrapper
      ['npm test', { test: 'cross-env CI=1 echo hi' }, 'missing'],
      ['npm test', { test: 'cross-env CI=1 jest || true' }, 'partial'],
      ['npm test', { test: 'cross-env CI=1 NODE_ENV=test jest' }, 'covered'],
      // the last command can't fail the script (sh -c, no -e)
      ['npm test', { test: 'node script.js || true' }, 'partial'],
      ['npm test', { test: 'node script.js; exit 0' }, 'partial'],
      ['npm test', { test: 'node script.js; true' }, 'partial'],
      ['npm test', { test: 'npm run a || true', a: 'jest' }, 'partial'],
      ['npm test', { test: 'npm run a', a: 'node x.js || true' }, 'partial'],
      // stays counted by name
      ['npm test', { test: 'node script.js' }, 'covered'],
      ['npm test', { test: 'jest && echo done' }, 'covered'],
      ['npm test', { test: 'npm run a && jest', a: 'echo ok' }, 'covered'], // P54: the script's last && chain
      ['npm test', { test: 'npm run a', a: 'tape test.js' }, 'covered'],
      ['npm test', { test: 'test -f x || exit 0; node t.js' }, 'partial'], // P53: after a conditional exit
    ] as [string, Record<string, string>, string][]) {
      const dir = makeTempDir();
      pkg(dir, scripts);
      wf(dir, 'ci.yml', PR(run(cmd)));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, JSON.stringify(scripts)).toBe(status);
    }
    for (const [scripts, status] of [
      [{ lint: 'npm run lint:js', 'lint:js': 'echo' }, 'missing'], [{ lint: 'eslint . || true' }, 'partial'],
      [{ lint: 'cross-env TIMING=1 eslint .' }, 'covered'], [{ lint: 'eslint --version' }, 'missing'],
    ] as [Record<string, string>, string][]) {
      const dir = makeTempDir();
      pkg(dir, scripts);
      wf(dir, 'ci.yml', PR(run('npm run lint')));
      expect(row(await coverage(dir), 'merge', 'lint', 'app').status, JSON.stringify(scripts)).toBe(status);
    }
  });

  it('N3: cross-env is a wrapper (`npm run ci` → `cross-env CI=1 jest` counts)', async () => {
    const dir = makeTempDir();
    pkg(dir, { ci: 'cross-env CI=1 jest' });
    wf(dir, 'ci.yml', PR(run('npm run ci')));
    expect(row(await coverage(dir), 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run ci`' });
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', PR(run('npx cross-env NODE_ENV=test jest --ci')));
    expect(row(await coverage(dir2), 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'jest' });
  });

  it('dead code in CI text too: right of `true ||` / `false &&` never runs', async () => {
    for (const [cmd, status] of [['true || jest', 'missing'], ['false && jest', 'missing'], ['echo x || (jest)', 'missing'], ['true || jest || exit 1', 'missing'],
      ['true && jest', 'covered'], ['false || jest', 'partial'], ['true || jest; jest', 'covered']]) { // P54: last && chain; P53: right of ||
      const dir = makeTempDir();
      wf(dir, 'ci.yml', PR(run(cmd as string)));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, cmd).toBe(status);
    }
  });

  it('N2: local hooks with language script, unsupported_script or docker_image never count by tool name', async () => {
    for (const language of ['script', 'unsupported_script', 'docker_image', 'fail', 'pygrep']) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', `repos:\n  - repo: local\n    hooks:\n      - id: x\n        name: x\n        entry: ruff check\n        language: ${language}\n`);
      expect(row(await coverage(dir, py), 'pre-commit', 'format-lint', 'app').status, language).toBe('missing');
    }
  });

  it('N4: SKIP set inside a local composite action the job uses makes hooks-in-CI partial', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
    writeIn(dir, '.github/actions/setskip/action.yml', 'runs:\n  using: composite\n  steps:\n    - run: echo "SKIP=ruff-check" >> "$GITHUB_ENV"\n      shell: bash\n');
    wf(dir, 'ci.yml', PR('      - uses: ./.github/actions/setskip\n' + run('pre-commit run --all-files')));
    const rows = await coverage(dir, py);
    expect(row(rows, 'merge', 'hooks-ci').status).toBe('partial');
    expect(row(rows, 'merge', 'lint', 'app').status).toBe('partial'); // P57 (C4): the hook SKIP names
    // the same composite action with an env key
    const dir2 = makeTempDir();
    writeIn(dir2, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
    writeIn(dir2, '.github/actions/a/action.yaml', 'runs:\n  using: composite\n  steps:\n    - run: pre-commit run --all-files\n      shell: bash\n      env:\n        SKIP: ruff-check\n');
    wf(dir2, 'ci.yml', PR('      - uses: ./.github/actions/a\n'));
    expect(row(await coverage(dir2, py), 'merge', 'hooks-ci').status).toBe('partial');
  });
});

// ---------- Task 5 fix round 3: the re-review's probes (task-5-rereview-2.md N6, N7) ----------

describe('mapCoverage (Task 5 fix round 3)', () => {
  const PR = (steps: string) => `on:\n  pull_request:\n${job(steps)}`;

  it('N6: a local composite action used 20,000 times is read once for the job gate (100 jobs × 200 uses of a 100 KB action)', async () => {
    const dir = makeTempDir();
    const line = '    - run: echo hello world this is padding text for the composite action body\n      shell: bash\n';
    writeIn(dir, '.github/actions/a/action.yml', `runs:\n  using: composite\n  steps:\n    - run: echo "SKIP=ruff-check" >> "$GITHUB_ENV"\n      shell: bash\n${line.repeat(Math.floor(100 * 1024 / line.length))}`);
    const stepsTxt = '      - uses: ./.github/actions/a\n'.repeat(200);
    const jobs = Array.from({ length: 100 }, (_, i) => `  j${i}:\n    runs-on: x\n    steps:\n${stepsTxt}`).join('');
    wf(dir, 'w.yml', `on: [pull_request]\njobs:\n${jobs}`);
    const started = Date.now();
    const rows = await coverage(dir);
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(rows.filter((r) => r.need.layer !== 'pre-commit').every((r) => r.status !== 'covered')).toBe(true);
  }, 30_000);

  it('N6: the cached composite gate applies to every job that uses the action (SKIP → hooks-in-CI partial)', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
    writeIn(dir, '.github/actions/a/action.yml', 'runs:\n  using: composite\n  steps:\n    - run: echo "SKIP=ruff-check" >> "$GITHUB_ENV"\n      shell: bash\n');
    const one = `    runs-on: x\n    steps:\n      - uses: ./.github/actions/a\n      - uses: ./.github/actions/a/\n${run('pre-commit run --all-files')}`;
    wf(dir, 'w.yml', `on: [pull_request]\njobs:\n  a:\n${one}  b:\n${one}`);
    wf(dir, 'x.yml', `on: [pull_request]\njobs:\n  c:\n${one}`);
    const rows = await coverage(dir, { services: [svc('.', { language: 'python', packageManager: 'uv', scripts: [] })] });
    expect(row(rows, 'merge', 'hooks-ci').status).toBe('partial');
    expect(row(rows, 'merge', 'lint', 'app').status).toBe('partial'); // P57 (C4): the hook SKIP names
  });

  it('N7: own-script calls are followed with no depth limit, through npm aliases, yarn <script>, run-s / run-p / npm-run-all and concurrently', async () => {
    const chain = (n: number, last: string) => Object.fromEntries([['test', 'npm run c1'], ...Array.from({ length: n }, (_, i) => [`c${i + 1}`, i + 1 === n ? last : `npm run c${i + 2}`])]);
    for (const [cmd, scripts, status] of [
      ['npm test', { test: 'npm-run-all a', a: 'echo' }, 'missing'],
      ['npm test', { test: 'run-s a b', a: 'echo', b: 'true' }, 'missing'],
      ['npm test', { test: 'run-p "test:*"', 'test:x': 'echo', 'test:y': ':' }, 'missing'],
      ['npm test', { test: 'run-p "test:*"', 'test:x': 'echo', 'test:y': 'jest' }, 'covered'],
      ['npm test', { test: 'run-s "test:**"', 'test:a:b': 'jest' }, 'covered'],
      ['npm test', { test: 'run-s "test:*" && echo', 'test:a:b': 'echo' }, 'covered'], // * stays inside one `:` part: no script matches, run-s fails, kept by name
      ['npm test', { test: 'run-s -c jestrun', jestrun: 'jest' }, 'partial'],
      ['npm test', { test: 'concurrently "npm:a"', a: 'echo' }, 'missing'],
      ['npm test', { test: 'concurrently --success first "npm:a" "npm:b"', a: 'jest', b: 'echo' }, 'partial'],
      ['npm test', { test: 'concurrently "npm:a" "node server.js"', a: 'echo' }, 'covered'], // a plain command isn't followed: by name
      ['yarn test', { test: 'echo ok' }, 'missing'],
      ['yarn test', { test: 'yarn a', a: 'echo' }, 'missing'],
      ['yarn test', { test: 'yarn a', a: 'jest' }, 'covered'],
      ['npm test', { test: 'npm run-script a', a: 'echo' }, 'missing'],
      ['npm test', { test: 'npm rum a', a: 'echo' }, 'missing'],
      ['npm test', { test: 'npm run-script a', a: 'jest' }, 'covered'],
      ['npm test', { test: 'npm run "my test"', 'my test': 'echo' }, 'missing'],
      ['npm test', { test: 'npm run a\\"b', 'a"b': 'echo' }, 'missing'],
      ['npm test', chain(5, 'echo'), 'missing'],
      ['npm test', chain(40, 'echo'), 'missing'],
      ['npm test', chain(40, 'jest'), 'covered'],
      ['npm test', { test: '(true) || jest' }, 'missing'],
      ['npm test', { test: '{ true; } || jest' }, 'missing'],
      ['npm test', { test: 'exit 00' }, 'missing'],
      ['npm test', { test: 'jest; exit 000' }, 'partial'],
      ['npm t', { test: 'jest' }, 'covered'],
      ['npm tst', { test: 'echo' }, 'missing'],
      ['npm run-script test', { test: 'jest' }, 'covered'],
      ['npm urn test', { test: 'jest' }, 'covered'],
    ] as [string, Record<string, string>, string][]) {
      const dir = makeTempDir();
      pkg(dir, scripts);
      wf(dir, 'ci.yml', PR(run(cmd)));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, `${cmd} ${JSON.stringify(scripts).slice(0, 120)}`).toBe(status);
    }
    const lint = makeTempDir();
    pkg(lint, { lint: 'run-s "lint:*"', 'lint:a': 'echo' });
    wf(lint, 'ci.yml', PR(run('npm run lint')));
    expect(row(await coverage(lint), 'merge', 'lint', 'app').status).toBe('missing');
  });

  it('N7: `npm run ci` → `run-s lint test` and `npm t` in CI are no longer false missing (content path)', async () => {
    const dir = makeTempDir();
    pkg(dir, { ci: 'run-s lint:js test:unit', 'lint:js': 'eslint .', 'test:unit': 'jest' });
    wf(dir, 'ci.yml', PR(run('npm run ci')));
    const rows = await coverage(dir);
    expect(row(rows, 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run ci`' });
    expect(row(rows, 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run ci`' });
    const direct = makeTempDir();
    pkg(direct, { 'lint:js': 'eslint .', 'test:unit': 'vitest run' });
    wf(direct, 'ci.yml', PR(run('npx run-p "lint:*" "test:*"')));
    const rows2 = await coverage(direct);
    expect(row(rows2, 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `run-p test:*`' });
    expect(row(rows2, 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'your own `run-p lint:*`' });
    const yarnScript = makeTempDir();
    pkg(yarnScript, { ci: 'jest' });
    wf(yarnScript, 'ci.yml', PR(run('yarn ci')));
    expect(row(await coverage(yarnScript), 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `yarn ci`' });
    const t = makeTempDir();
    pkg(t, { test: 'jest' });
    wf(t, 'ci.yml', PR(run('npm t')));
    expect(row(await coverage(t), 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm t`' });
  });

  it('N7: past the script cap (1,000) a by-name script is unknown, never covered', async () => {
    const dir = makeTempDir();
    const scripts: Record<string, string> = { test: 'npm run c0' };
    for (let i = 0; i < 1200; i++) scripts[`c${i}`] = `npm run c${i + 1}`;
    scripts.c1200 = 'echo';
    pkg(dir, scripts);
    wf(dir, 'ci.yml', PR(run('npm test')));
    const started = Date.now();
    const r = row(await coverage(dir), 'merge', 'unit-tests', 'app');
    expect(Date.now() - started).toBeLessThan(5000);
    expect(r.status).toBe('unknown');
    expect(r.why).toBe("There are more package scripts than pipegen follows (1,000), so it can't tell what your own `npm test` runs.");
  });
});

// ---------- Task 5 fix round 4: the re-review's probes (task-5-rereview-3.md N8, N9) ----------

describe('mapCoverage (Task 5 fix round 4)', () => {
  const py = { services: [svc('.', { language: 'python', packageManager: 'uv', scripts: [] })] };
  const PR = (steps: string) => `on:\n  pull_request:\n${job(steps)}`;
  /** Keys of 200 characters, each matched in vain by the patterns below (the re-review's glob-cost shapes). */
  const longKeys = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => ['a'.repeat(194) + String(i).padStart(6, '0'), 'echo']));
  const timed = async (dir: string, over: Partial<RepoProfile> = {}) => {
    const started = Date.now();
    const rows = await coverage(dir, over);
    return { rows, ms: Date.now() - started };
  };

  it('N8: `run-s "t:*"` over 5,000 scripts, only the last running jest, is unknown, never missing (no truncated list decides the row)', async () => {
    const scripts: Record<string, string> = { test: 'run-s "t:*"' };
    for (let i = 0; i < 5000; i++) scripts[`t:${i}`] = i === 4999 ? 'jest' : 'echo';
    const byName = makeTempDir();
    pkg(byName, scripts);
    wf(byName, 'ci.yml', PR(run('npm test')));
    expect(row(await coverage(byName), 'merge', 'unit-tests', 'app').status).toBe('unknown');
    // the same glob on a CI line (content path)
    const content = makeTempDir();
    pkg(content, scripts);
    wf(content, 'ci.yml', PR(run('npx run-s "t:*"')));
    expect(row(await coverage(content), 'merge', 'unit-tests', 'app').status).toBe('unknown');
  }, 30_000);

  it('N8: more than 16 patterns, or a pattern pipegen does not read, makes the call unknown', async () => {
    const names = Array.from({ length: 17 }, (_, i) => `s${i}`);
    const scripts = Object.fromEntries(names.map((n) => [n, 'echo']));
    for (const [line, status] of [
      [`run-s ${names.slice(0, 16).join(' ')}`, 'missing'],
      [`run-s ${names.join(' ')}`, 'unknown'],
      ['run-s "s{0,1}"', 'unknown'],
      ['run-s "s?"', 'unknown'],
      [`run-s "${'s'.repeat(65)}*"`, 'unknown'],
    ] as const) {
      const dir = makeTempDir();
      pkg(dir, { ...scripts, test: line });
      wf(dir, 'ci.yml', PR(run('npm test')));
      expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status, line).toBe(status);
      const content = makeTempDir();
      pkg(content, scripts);
      wf(content, 'ci.yml', PR(run(`npx ${line}`)));
      expect(row(await coverage(content), 'merge', 'unit-tests', 'app').status, `CI: ${line}`).toBe(status === 'missing' ? 'missing' : 'unknown');
    }
  });

  it('N8: a script name longer than 64 characters never matches a glob', async () => {
    const dir = makeTempDir();
    pkg(dir, { test: 'run-s "t:*"', [`t:${'x'.repeat(70)}`]: 'jest' });
    wf(dir, 'ci.yml', PR(run('npx run-s "t:*"')));
    expect(row(await coverage(dir), 'merge', 'unit-tests', 'app').status).toBe('missing');
  });

  it('N8: one `npm test` whose script runs 60 glob patterns over 3,000 keys takes under 2 s and is never covered', async () => {
    const dir = makeTempDir();
    const P = '*a'.repeat(120) + 'b';
    pkg(dir, { test: 'run-s ' + Array.from({ length: 60 }, () => `"${P}"`).join(' '), ...longKeys(3000) });
    wf(dir, 'ci.yml', PR(run('npm test')));
    const { rows, ms } = await timed(dir);
    expect(ms).toBeLessThan(2000);
    expect(row(rows, 'merge', 'unit-tests', 'app').status).toBe('unknown');
  }, 30_000);

  for (const lines of [1, 5]) {
    it(`N8: ${lines} CI line(s) of \`npx run-s\` with 60 patterns of 63 characters over 3,000 keys take under 2 s`, async () => {
      const dir = makeTempDir();
      pkg(dir, longKeys(3000));
      const P = '*a'.repeat(31) + 'b';
      const line = 'npx run-s ' + Array.from({ length: 60 }, (_, j) => P.slice(0, 61) + String(j).padStart(2, '0')).join(' ');
      wf(dir, 'ci.yml', PR(run(line).repeat(lines)));
      const { rows, ms } = await timed(dir);
      expect(ms).toBeLessThan(2000);
      expect(row(rows, 'merge', 'unit-tests', 'app').status).toBe('unknown');
    }, 30_000);
  }

  it('N8: glob work past the budget is capped: 60 scripts × 16 distinct 64-character globs over 3,000 64-character names take under 2 s and are unknown', async () => {
    const dir = makeTempDir();
    const scripts: Record<string, string> = { test: Array.from({ length: 60 }, (_, i) => `npm run g${i}`).join(' && ') };
    for (let i = 0; i < 60; i++) scripts[`g${i}`] = 'run-p ' + Array.from({ length: 16 }, (_, j) => `"${'*a'.repeat(29)}${String(i * 16 + j).padStart(5, '0')}*"`).join(' ');
    for (let i = 0; i < 3000; i++) scripts['a'.repeat(58) + String(i).padStart(6, '0')] = 'echo';
    pkg(dir, scripts);
    wf(dir, 'ci.yml', PR(run('npm test')));
    const { rows, ms } = await timed(dir);
    expect(ms).toBeLessThan(2000);
    expect(row(rows, 'merge', 'unit-tests', 'app').status).toBe('unknown');
  }, 30_000);

  // N9: SKIP written to GITHUB_ENV inside a local action pipegen can't fully read (the runner does read it)
  const SET_SKIP = 'runs:\n  using: composite\n  steps:\n    - run: echo "SKIP=ruff-check" >> "$GITHUB_ENV"\n      shell: bash\n';
  const hidden = async (setup: (dir: string) => string) => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
    const uses = setup(dir);
    wf(dir, 'ci.yml', PR(uses + run('pre-commit run --all-files')));
    const rows = await coverage(dir, py);
    return [row(rows, 'merge', 'hooks-ci').status, row(rows, 'merge', 'lint', 'app').status];
  };
  // The gate turns `pre-commit run` partial (SKIP may be set) and carries no lint over; the step pipegen couldn't read
  // into is opaque, and an opaque run outranks a partial one, so both rows are unknown (at ae4ab8c both were covered).

  it('N9: a local action reached through a symbolic link gets the can\'t-tell gate', async () => {
    const [hooks, lint] = await hidden((dir) => {
      writeIn(dir, 'a/action.yml', SET_SKIP);
      symlinkSync(join(dir, 'a'), join(dir, 'ln'));
      return '      - uses: ./ln\n';
    });
    expect([hooks, lint]).toEqual(['unknown', 'unknown']);
  });

  it('N9: a composite action that calls another local action gets the can\'t-tell gate', async () => {
    const [hooks, lint] = await hidden((dir) => {
      writeIn(dir, 'a/action.yml', SET_SKIP);
      writeIn(dir, 'outer/action.yml', 'runs:\n  using: composite\n  steps:\n    - uses: ./a\n');
      return '      - uses: ./outer\n';
    });
    expect([hooks, lint]).toEqual(['unknown', 'unknown']);
  });

  it('N9: a local action past the local-file cap gets the can\'t-tell gate', async () => {
    const [hooks, lint] = await hidden((dir) => {
      for (let i = 0; i < 150; i++) writeIn(dir, `acts/a${i}/action.yml`, i === 149 ? SET_SKIP : 'runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n');
      return Array.from({ length: 150 }, (_, i) => `      - uses: ./acts/a${i}\n`).join('');
    });
    expect([hooks, lint]).toEqual(['unknown', 'unknown']);
  });

  it('N9: a local action that can\'t be read (not valid YAML) gets the can\'t-tell gate', async () => {
    const [hooks, lint] = await hidden((dir) => {
      writeIn(dir, 'a/action.yml', `${SET_SKIP}  : [\n`);
      return '      - uses: ./a\n';
    });
    expect([hooks, lint]).toEqual(['unknown', 'unknown']);
  });

  it('N9: a missing local action adds no gate; a non-composite one may set SKIP (Plan P Task 3 ruling P9)', async () => {
    const [missingHooks] = await hidden(() => '      - uses: ./nope\n');
    expect(missingHooks).toBe('covered');
    const [nodeHooks] = await hidden((dir) => {
      writeIn(dir, 'n/action.yml', "runs:\n  using: node20\n  main: index.js\n");
      return '      - uses: ./n\n';
    });
    expect(nodeHooks).toBe('unknown'); // its own code can write SKIP to GITHUB_ENV, so the run isn't covered, and the action is opaque
  });
});

// ---------- Plan U final review I2: a visible TOX… / NOX… variable makes the run partial, never missing ----------

describe('mapCoverage (Plan U final review I2)', () => {
  const TOX_WHY = "Your own `tox run` runs, but a TOX… variable in this job (like TOXENV) picks which tox environments run, so pipegen can't tell if it runs the tests.";
  const testRows = (rows: Coverage[]) => [row(rows, 'push', 'unit-tests', 'app'), row(rows, 'merge', 'unit-tests', 'app'), row(rows, 'merge', 'full-tests', 'app')];

  it('I2: the flask shape (TOX_ENV from the matrix on `uv run … tox run`) → partial with a plain why, never covered or missing', async () => {
    const dir = makeTempDir();
    const matrix = "    strategy:\n      matrix:\n        include:\n          - {python: '3.14'}\n          - {name: Minimum Versions, python: '3.14', tox: tests-min}\n";
    const steps = '      - uses: actions/checkout@v4\n      - run: uv run --locked --no-default-groups --group dev tox run\n'
      + "        env:\n          TOX_ENV: ${{ matrix.tox || format('py{0}', matrix.python) }}\n";
    ci(dir, steps, matrix);
    for (const r of testRows(await coverage(dir, pyApp))) expect(r, `${r.need.layer} ${r.need.id}`).toMatchObject({ status: 'partial', by: 'your own `tox run`', why: TOX_WHY });
  });

  it('I2: TOXENV from a matrix value, set for the step, the job or the workflow, inline or through GITHUB_ENV → partial', async () => {
    const matrix = '    strategy:\n      matrix:\n        toxenv: [py312, py313]\n';
    for (const [body, by] of [
      [`${both}${job('      - run: tox run\n        env:\n          TOXENV: ${{ matrix.toxenv }}\n', matrix)}`, 'your own `tox run`'],
      [`${both}${job(run('tox'), `${matrix}    env:\n      TOXENV: \${{ matrix.toxenv }}\n`)}`, 'your own `tox`'],
      [`${both}env:\n  TOXENV: lint\n${job(run('tox'))}`, 'your own `tox`'],
      [`${both}${job(run('TOXENV=lint tox'))}`, 'your own `tox`'],
      [`${both}${job(run('echo "TOXENV=lint" >> "$GITHUB_ENV"') + run('tox run'))}`, 'your own `tox run`'],
    ]) {
      const dir = makeTempDir();
      wf(dir, 'ci.yml', body as string);
      for (const r of testRows(await coverage(dir, pyApp))) {
        expect(r.status, body).toBe('partial');
        expect(r.by, body).toBe(by);
        expect(r.why, body).toMatch(/a TOX… variable in this job \(like TOXENV\) picks which tox environments run, so pipegen can't tell if it runs the tests\.$/);
      }
    }
  });

  it('I2: a NOX… variable (NOXSESSION) makes a nox run partial the same way', async () => {
    const dir = makeTempDir();
    ci(dir, '      - run: nox\n        env:\n          NOXSESSION: ${{ matrix.session }}\n');
    for (const r of testRows(await coverage(dir, pyApp))) {
      expect(r).toMatchObject({ status: 'partial', by: 'your own `nox`' });
      expect(r.why).toBe("Your own `nox` runs, but a NOX… variable in this job (like NOXSESSION) picks which nox sessions run, so pipegen can't tell if it runs the tests.");
    }
  });

  it('I2: another run that covers the tests still wins over the partial tox run', async () => {
    const dir = makeTempDir();
    ci(dir, '      - run: tox run\n        env:\n          TOXENV: ${{ matrix.toxenv }}\n' + run('pytest'));
    expect(row(await coverage(dir, pyApp), 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `pytest`' });
  });
});

// ---------- Plan P Task 3: the catalogue's tools in workflows and hooks ----------

describe('mapCoverage (Plan P Task 3)', () => {
  const q = emptyServiceQuality();
  const tsSvc = (over: Partial<Service> = {}) => svc('.', { quality: { ...q, tsconfig: true }, ...over });
  const dockerSvc = svc('.', { scripts: ['start'], dockerfile: 'Dockerfile' });
  const pySvc = svc('.', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...q, pythonTyped: true } });
  /** mapCoverage with options (capabilities), over a profile read from `dir`. */
  async function cov(dir: string, over: Partial<RepoProfile> = {}, opts: Parameters<typeof mapCoverage>[3] = {}): Promise<Coverage[]> {
    const p = await profileOf(dir, over);
    return mapCoverage(p, floorNeeds(p, caps), dir, opts);
  }
  async function rowOf(body: string, layer: Layer, id: string, over: Partial<RepoProfile> = {}, service?: string, opts: Parameters<typeof mapCoverage>[3] = {}, file = 'ci.yml'): Promise<Coverage> {
    const dir = makeTempDir();
    wf(dir, file, body);
    return row(await cov(dir, over, opts), layer, id, service);
  }
  const ciRun = (cmd: string) => `${both}${job(run(cmd))}`;
  const ciUses = (uses: string, withLines = '') => `${both}${job(`      - uses: ${uses}\n${withLines === '' ? '' : `        with:\n${withLines}`}`)}`;

  it('coverage: Dockerfile without an image build → hadolint covers dockerfile-lint only; trivy config alone is partial', async () => {
    const over = { services: [dockerSvc] };
    const dir = makeTempDir();
    wf(dir, 'ci.yml', ciRun('hadolint Dockerfile'));
    const rows = await cov(dir, over);
    expect(row(rows, 'merge', 'dockerfile-lint', 'app')).toMatchObject({ status: 'covered', by: 'hadolint' });
    expect(row(rows, 'push', 'dockerfile-lint', 'app')).toMatchObject({ status: 'covered', by: 'hadolint' });
    expect(row(rows, 'merge', 'image-scan', 'app').status).toBe('missing');
    expect(row(rows, 'merge', 'image-build', 'app').status).toBe('missing');
    const t = await rowOf(ciRun('trivy config --exit-code 1 .'), 'merge', 'dockerfile-lint', over, 'app');
    expect(t).toMatchObject({ status: 'partial', by: 'trivy-dockerfile' });
    expect(t.why).toBe('Trivy config checks Dockerfile security settings, not the shell in RUN lines; hadolint adds that.');
  });

  it('coverage: trivy config --exit-code 1 with a Dockerfile → image-scan missing (PB3)', async () => {
    expect((await rowOf(ciRun('trivy config --exit-code 1 .'), 'merge', 'image-scan', { services: [dockerSvc] }, 'app')).status).toBe('missing');
  });

  it('coverage: PB3 trivy and grype count by subcommand and target', async () => {
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    const over = { services: [dockerSvc] };
    const st = async (body: string, id: string, layer: Layer = 'merge') => {
      const r = await rowOf(body, layer, id, over, 'app');
      return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
    };
    expect(await st(ciRun('trivy image --exit-code 1 app:1'), 'image-scan')).toBe('covered trivy-image');
    expect(await st(ciRun('trivy image --exit-code 1 app:1'), 'deps')).toBe('missing');
    expect(await st(ciRun('trivy i --exit-code 1 app:1'), 'image-scan')).toBe('covered trivy-image');
    expect(await st(ciRun('trivy image app:1'), 'image-scan')).toBe('partial trivy-image'); // exits 0 without --exit-code
    expect(await st(ciRun('trivy image --scanners misconfig --exit-code 1 app:1'), 'image-scan')).toBe('missing'); // no vulnerability scan
    expect(await st(ciRun('trivy image --scanners vuln,secret --exit-code 1 app:1'), 'image-scan')).toBe('covered trivy-image');
    expect(await st(ciRun('trivy fs --exit-code 1 .'), 'deps')).toBe('covered trivy-fs');
    expect(await st(ciRun('trivy fs --exit-code 1 .'), 'image-scan')).toBe('missing');
    expect(await st(ciRun('trivy repo --exit-code 1 .'), 'deps')).toBe('covered trivy-fs');
    expect(await st(ciRun('trivy clean --all'), 'deps')).toBe('missing');
    expect(await st(ciRun('trivy --exit-code 1 app:1'), 'image-scan')).toBe('missing'); // no subcommand: not a run pipegen knows
    // trivy-action by scan-type (default image)
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          exit-code: '1'\n"), 'image-scan')).toBe('covered trivy-image');
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          exit-code: '1'\n"), 'deps')).toBe('missing');
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          scan-type: fs\n          exit-code: '1'\n"), 'deps')).toBe('covered trivy-fs');
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          scan-type: fs\n          exit-code: '1'\n"), 'image-scan')).toBe('missing');
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          scan-type: config\n          exit-code: '1'\n"), 'image-scan')).toBe('missing');
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          scan-type: ${{ matrix.t }}\n          exit-code: '1'\n"), 'image-scan')).toBe('missing');
    expect(await st(ciUses('aquasecurity/trivy-action@0.33.1', "          exit-code: '1'\n          trivy-config: trivy.yaml\n"), 'image-scan')).toBe('partial trivy-image');
    // grype: a folder or SBOM is a dependency scan, an image reference an image scan, anything else can't be placed
    expect(await st(ciRun('grype dir:. --fail-on high'), 'deps', 'push')).toBe('covered grype');
    expect(await st(ciRun('grype dir:. --fail-on high'), 'image-scan')).toBe('missing');
    expect(await st(ciRun('grype . --fail-on high'), 'image-scan')).toBe('missing');
    expect(await st(ciRun('grype sbom:./sbom.json --fail-on high'), 'image-scan')).toBe('missing');
    expect(await st(ciRun('grype ghcr.io/o/app:1.2 --fail-on high'), 'image-scan')).toBe('covered grype-image');
    expect(await st(ciRun('grype registry:o/app --fail-on high'), 'image-scan')).toBe('covered grype-image');
    expect(await st(ciRun('grype "$IMAGE" --fail-on high'), 'image-scan')).toBe('partial grype-image');
    expect(await st(ciRun('grype app --fail-on high'), 'image-scan')).toBe('partial grype-image');
    expect(await st(ciRun('grype app:1 dir:. --fail-on high'), 'image-scan')).toBe('missing'); // a folder named too: not counted
    expect(await st(ciUses('anchore/scan-action@v7', '          image: app:1\n'), 'image-scan')).toBe('covered grype-image');
    expect(await st(ciUses('anchore/scan-action@v7', '          path: .\n'), 'image-scan')).toBe('missing');
    expect(await st(ciUses('anchore/scan-action@v7', '          path: .\n'), 'deps', 'push')).toBe('covered grype');
    expect(await st(ciUses('anchore/scan-action@v7', '          image: app:1\n          config: .grype.yaml\n'), 'image-scan')).toBe('partial grype-image');
  });

  it('coverage: prettier without --check → format missing; prettier --check → covered', async () => {
    expect((await rowOf(ciRun('prettier --write .'), 'merge', 'format', {}, 'app')).status).toBe('missing');
    expect((await rowOf(ciRun('npx prettier .'), 'merge', 'format', {}, 'app')).status).toBe('missing');
    for (const cmd of ['npx prettier --check .', 'prettier -c .', 'prettier --list-different .', 'prettier -l .']) {
      expect(await rowOf(ciRun(cmd), 'merge', 'format', {}, 'app'), cmd).toMatchObject({ status: 'covered', by: 'prettier-check' });
    }
    expect((await rowOf(ciRun('prettier --check --write .'), 'merge', 'format', {}, 'app')).status).toBe('missing');
    expect((await rowOf(ciRun('prettier --check=false .'), 'merge', 'format', {}, 'app')).status).toBe('missing');
  });

  it('coverage: biome ci covers lint and format; biome check --write covers lint only', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', ciRun('npx @biomejs/biome ci .'));
    let rows = await cov(dir);
    expect(row(rows, 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'biome' });
    expect(row(rows, 'merge', 'format', 'app')).toMatchObject({ status: 'covered', by: 'biome-ci' });
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', ciRun('biome check --write .'));
    rows = await cov(dir2);
    expect(row(rows, 'merge', 'lint', 'app')).toMatchObject({ status: 'covered', by: 'biome' });
    expect(row(rows, 'merge', 'format', 'app').status).toBe('missing');
    for (const cmd of ['biome ci --formatter-enabled=false .', 'biome check --fix .', 'biome format --write .', 'biome format --staged']) {
      expect((await rowOf(ciRun(cmd), 'merge', 'format', {}, 'app')).status, cmd).toBe('missing');
    }
    expect(await rowOf(ciRun('biome format .'), 'merge', 'format', {}, 'app')).toMatchObject({ status: 'covered', by: 'biome-format-check' });
    expect((await rowOf(ciRun('biome migrate --write'), 'merge', 'lint', {}, 'app')).status).toBe('missing'); // not a lint run
  });

  it('coverage: ruff format --check covers format; ruff format alone doesn\'t', async () => {
    const over = { services: [pySvc] };
    expect(await rowOf(ciRun('ruff format --check .'), 'merge', 'format', over, 'app')).toMatchObject({ status: 'covered', by: 'ruff-format-check' });
    expect(await rowOf(ciRun('uv run ruff format --diff'), 'merge', 'format', over, 'app')).toMatchObject({ status: 'covered', by: 'ruff-format-check' });
    expect((await rowOf(ciRun('ruff format .'), 'merge', 'format', over, 'app')).status).toBe('missing');
    expect(await rowOf(ciRun('black --check .'), 'merge', 'format', over, 'app')).toMatchObject({ status: 'covered', by: 'black-check' });
    expect((await rowOf(ciRun('black --diff .'), 'merge', 'format', over, 'app')).status).toBe('missing'); // --diff alone exits 0
    expect((await rowOf(ciRun('black .'), 'merge', 'format', over, 'app')).status).toBe('missing');
  });

  it('coverage: tsc --noEmit on push covers type-check; tsc --watch doesn\'t', async () => {
    const over = { services: [tsSvc()] };
    expect(await rowOf(`on: push\n${job(run('npx tsc --noEmit'))}`, 'push', 'type-check', over, 'app')).toMatchObject({ status: 'covered', by: 'tsc' });
    for (const cmd of ['tsc --watch', 'tsc -w', 'tsc --noCheck', 'tsc --init', 'tsc --showConfig', 'tsc --listFilesOnly', 'tsc --build --clean']) {
      expect((await rowOf(`on: push\n${job(run(cmd))}`, 'push', 'type-check', over, 'app')).status, cmd).toBe('missing');
    }
    for (const cmd of ['vue-tsc --noEmit', 'svelte-check', 'astro check', 'tsgo --noEmit']) {
      expect((await rowOf(`on: push\n${job(run(cmd))}`, 'push', 'type-check', over, 'app')).status, cmd).toBe('covered');
    }
    expect(await rowOf(`on: push\n${job(run('oxlint --type-aware --type-check'))}`, 'push', 'type-check', over, 'app')).toMatchObject({ status: 'covered', by: 'oxlint-type-check' });
    expect((await rowOf(`on: push\n${job(run('oxlint --type-aware'))}`, 'push', 'type-check', over, 'app')).status).toBe('missing');
    // oxlint fails only on errors: warnings (its default) need --deny-warnings
    expect(await rowOf(`on: push\n${job(run('oxlint'))}`, 'push', 'lint', over, 'app')).toMatchObject({ status: 'partial', by: 'oxlint' });
    expect(await rowOf(`on: push\n${job(run('oxlint --deny-warnings'))}`, 'push', 'lint', over, 'app')).toMatchObject({ status: 'covered', by: 'oxlint' });
    // mypy and pyright for Python
    const py = { services: [pySvc] };
    expect(await rowOf(`on: push\n${job(run('uv run mypy src'))}`, 'push', 'type-check', py, 'app')).toMatchObject({ status: 'covered', by: 'mypy' });
    expect(await rowOf(`on: push\n${job(run('pyright'))}`, 'push', 'type-check', py, 'app')).toMatchObject({ status: 'covered', by: 'pyright' });
    expect((await rowOf(`on: push\n${job(run('pyright --watch'))}`, 'push', 'type-check', py, 'app')).status).toBe('missing');
    expect((await rowOf(`on: push\n${job(run('basedpyright --writebaseline'))}`, 'push', 'type-check', py, 'app')).status).toBe('missing');
  });

  it('coverage: knip --no-exit-code → dead-code partial for a knip-config service, covered when not blocking', async () => {
    const knip = { services: [svc('.', { quality: { ...q, configs: ['knip'] } })] };
    const r = await rowOf(ciRun('npx knip --no-exit-code'), 'merge', 'dead-code', knip, 'app');
    expect(r).toMatchObject({ status: 'partial', by: 'knip' });
    expect(r.need.blocking).toBe(true);
    expect(await rowOf(ciRun('npx knip'), 'merge', 'dead-code', knip, 'app')).toMatchObject({ status: 'covered', by: 'knip' });
    expect((await rowOf(ciRun('npx knip --max-issues 5'), 'merge', 'dead-code', knip, 'app')).status).toBe('partial');
    const plain = await rowOf(ciRun('npx knip --no-exit-code'), 'merge', 'dead-code', {}, 'app');
    expect(plain.need.blocking).toBe(false);
    expect(plain).toMatchObject({ status: 'covered', by: 'knip' });
    expect((await rowOf(ciRun('npx knip --watch'), 'merge', 'dead-code', {}, 'app')).status).toBe('missing');
    const py = { services: [pySvc] };
    for (const [cmd, by] of [['vulture src', 'vulture'], ['deptry .', 'deptry'], ['creosote --venv .venv', 'creosote']]) {
      expect(await rowOf(ciRun(cmd), 'merge', 'dead-code', py, 'app'), cmd).toMatchObject({ status: 'covered', by });
    }
    expect(await rowOf(ciRun('go mod tidy -diff'), 'merge', 'dead-code', goApp, 'app')).toMatchObject({ status: 'covered', by: 'go-mod-tidy' });
    expect((await rowOf(ciRun('go mod tidy'), 'merge', 'dead-code', goApp, 'app')).status).toBe('unknown'); // not covered; Go is a stack pipegen doesn't support yet, so not missing either
  });

  it('coverage: pinact run without --check → workflow-pin-check missing', async () => {
    expect((await rowOf(ciRun('pinact run'), 'merge', 'workflow-pin-check')).status).toBe('missing');
    expect((await rowOf(ciRun('pinact run --check=false'), 'merge', 'workflow-pin-check')).status).toBe('missing');
    expect(await rowOf(ciRun('pinact run --check'), 'merge', 'workflow-pin-check')).toMatchObject({ status: 'covered', by: 'pinact' });
    expect(await rowOf(ciRun('pinact run --fix=false'), 'merge', 'workflow-pin-check')).toMatchObject({ status: 'covered', by: 'pinact' });
    expect(await rowOf(ciRun('ratchet lint .github/workflows/ci.yml'), 'merge', 'workflow-pin-check')).toMatchObject({ status: 'covered', by: 'ratchet' });
    const z = await rowOf(ciRun('zizmor .'), 'merge', 'workflow-pin-check');
    expect(z).toMatchObject({ status: 'partial', by: 'zizmor-pins' });
    expect(z.why).toMatch(/^Zizmor checks action pins, but a zizmor config or a version before v1\.20\.0 can allow tag pins/); // the source moved on from the brief's text
  });

  it('coverage: workflow lint: actionlint, zizmor, poutine, ghalint and their soft modes', async () => {
    const st = async (body: string) => {
      const r = await rowOf(body, 'merge', 'workflow-lint');
      return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
    };
    expect(await st(ciRun('actionlint'))).toBe('covered actionlint');
    expect(await st(ciUses('raven-actions/actionlint@v2'))).toBe('covered actionlint');
    expect(await st(ciUses('raven-actions/actionlint@v2', '          fail-on-error: false\n'))).toBe('partial actionlint');
    expect(await st(ciRun('zizmor .'))).toBe('covered zizmor');
    expect(await st(ciRun('zizmor --no-exit-codes .'))).toBe('partial zizmor');
    expect(await st(ciRun('zizmor --format=sarif .'))).toBe('partial zizmor');
    expect(await st(ciUses('zizmorcore/zizmor-action@v0.2.0'))).toBe('partial zizmor'); // advanced-security defaults to true: SARIF, no exit code
    // Ruling P33: zizmor-action is on pipegen's never-list (beta), so it is never covered, whatever its inputs
    expect(await st(ciUses('zizmorcore/zizmor-action@v0.2.0', '          advanced-security: false\n'))).toBe('partial zizmor');
    expect(await st(ciRun('poutine analyze_local .'))).toBe('partial poutine');
    expect(await st(ciRun('poutine analyze_local . --fail-on-violation'))).toBe('covered poutine');
    expect(await st(ciRun('ghalint run'))).toBe('covered ghalint');
  });

  it('coverage: osv reusable PR workflow → dependency-review covered, not unknown', async () => {
    const call = (ref: string, withLines = '') => `on:\n  pull_request:\njobs:\n  osv:\n    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@${ref}\n${withLines}`;
    const r = await rowOf(call('v2.3.0'), 'merge', 'dependency-review');
    expect(r).toMatchObject({ status: 'covered', by: 'osv-pr-diff', where: '.github/workflows/ci.yml (job osv)' });
    expect((await rowOf(call('1f1242919d8a60496dd1874b24b62b2370ed4c78'), 'merge', 'dependency-review')).status).toBe('covered');
    expect(await rowOf(call('main'), 'merge', 'dependency-review')).toMatchObject({ status: 'partial', by: 'osv-pr-diff' }); // a moving ref
    expect((await rowOf(call('v2.3.0', '    with:\n      fail-on-vuln: false\n'), 'merge', 'dependency-review')).status).toBe('partial');
    expect((await rowOf(call('v2.3.0', '    with:\n      fail-on-vuln: ${{ inputs.f }}\n'), 'merge', 'dependency-review')).status).toBe('partial');
    expect((await rowOf(call('v2.3.0', "    if: github.event_name == 'push'\n"), 'merge', 'dependency-review')).status).toBe('partial');
    // the other rows know what it runs (osv-scanner on the diff only), so they aren't unknown
    expect((await rowOf(call('v2.3.0'), 'merge', 'sast', {}, 'app')).status).toBe('missing');
  });

  it('coverage: reusableWorkflows (adversarial): look-alike paths stay unknown', async () => {
    for (const uses of [
      'google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2.3.0', // the full scan, not the PR diff
      'g00gle/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@v2.3.0',
      'google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yaml@v2.3.0',
      'google/osv-scanner-action/.github/workflows/sub/osv-scanner-reusable-pr.yml@v2.3.0',
      'google/osv-scanner-action/osv-scanner-reusable-pr.yml@v2.3.0',
    ]) {
      const r = await rowOf(`on:\n  pull_request:\njobs:\n  osv:\n    uses: ${uses}\n`, 'merge', 'dependency-review');
      expect(r.status, uses).toBe('unknown');
    }
    // letter case of owner and name doesn't matter on GitHub
    expect((await rowOf('on:\n  pull_request:\njobs:\n  osv:\n    uses: Google/OSV-Scanner-Action/.github/workflows/osv-scanner-reusable-pr.yml@v2.3.0\n', 'merge', 'dependency-review')).status).toBe('covered');
  });

  it('coverage: dependency-review-action on a user-owned private repo → partial with the availability why', async () => {
    const body = ciUses('actions/dependency-review-action@v5');
    const userPrivate = { private: true, ownerType: 'User' as const };
    const r = await rowOf(body, 'merge', 'dependency-review', userPrivate);
    expect(r).toMatchObject({ status: 'partial', by: 'dependency-review' });
    expect(r.why).toMatch(/^Dependency review works only on public repos and on organisation-owned private repos with GitHub Advanced Security/);
    expect((await rowOf(body, 'merge', 'deps', userPrivate, 'app')).status).toBe('partial');
    // user-owned private stays partial even when the capabilities say code scanning (R4)
    expect((await rowOf(body, 'merge', 'dependency-review', userPrivate, undefined, { capabilities: caps })).status).toBe('partial');
    // org-owned private: only with code scanning; without capabilities pipegen assumes none
    const orgPrivate = { private: true, ownerType: 'Organization' as const };
    expect((await rowOf(body, 'merge', 'dependency-review', orgPrivate)).status).toBe('partial');
    expect((await rowOf(body, 'merge', 'dependency-review', orgPrivate, undefined, { capabilities: { ...caps, codeScanning: false } })).status).toBe('partial');
    expect((await rowOf(body, 'merge', 'dependency-review', orgPrivate, undefined, { capabilities: caps })).status).toBe('covered');
    expect(await rowOf(body, 'merge', 'dependency-review')).toMatchObject({ status: 'covered', by: 'dependency-review' }); // public
    expect((await rowOf(ciUses('actions/dependency-review-action@v5', '          vulnerability-check: false\n'), 'merge', 'dependency-review')).status).toBe('missing');
    expect((await rowOf(ciUses('actions/dependency-review-action@v5', '          config-file: ./.github/dr.yml\n'), 'merge', 'dependency-review')).status).toBe('partial');
  });

  // DoD G11 (reviews/dod/2026-10-29/g11-licences.md): Trivy files every licence it can't classify under UNKNOWN, so
  // `--severity HIGH,CRITICAL` hides them all and exits 0; and pnpm-lock.yaml, bun.lock, uv.lock, requirements files and
  // go.mod give no licence data unless the packages are installed first (uv.lock never, in Trivy 0.76.0).
  it('coverage: a Trivy licence scan filtered to severities without UNKNOWN is partial, saying why (DoD G11)', async () => {
    neverOff.on = true;
    const pr = (cmd: string) => `on: pull_request\n${job(run(cmd))}`;
    const filtered = await rowOf(pr('trivy fs --scanners license --severity HIGH,CRITICAL --exit-code 1 .'), 'merge', 'licences');
    expect(filtered).toMatchObject({ status: 'partial', by: 'trivy-license' });
    expect(filtered.why).toMatch(/UNKNOWN/);
    expect((await rowOf(pr('trivy fs --scanners license --severity=CRITICAL --exit-code 1 .'), 'merge', 'licences')).status).toBe('partial');
    expect((await rowOf(pr('trivy fs --scanners license -s HIGH,CRITICAL --exit-code 1 .'), 'merge', 'licences')).status).toBe('partial');
    expect((await rowOf(pr('trivy fs --scanners license --severity UNKNOWN,HIGH,CRITICAL --exit-code 1 .'), 'merge', 'licences')).status).toBe('covered');
    // the action: its severity input, and TRIVY_SEVERITY in the job
    const act = (withLines: string) => `on: pull_request\n${job(`      - uses: aquasecurity/trivy-action@76071ef0d7ec797419534a183b498b4d6366cf37\n        with:\n          scan-type: fs\n          scanners: license\n          exit-code: '1'\n${withLines}`)}`;
    expect((await rowOf(act(''), 'merge', 'licences')).status).toBe('covered');
    expect((await rowOf(act("          severity: 'HIGH,CRITICAL'\n"), 'merge', 'licences')).status).toBe('partial');
    expect((await rowOf(`on: pull_request\n${job(run('trivy fs --scanners license --exit-code 1 .'), '    env:\n      TRIVY_SEVERITY: HIGH,CRITICAL\n')}`, 'merge', 'licences')).status).toBe('partial');
  });

  it('coverage: a Trivy licence scan over a lockfile that holds no licences without an install is partial (DoD G11)', async () => {
    neverOff.on = true;
    const body = `on: pull_request\n${job(run('trivy fs --scanners license --exit-code 1 .'))}`;
    for (const packageManager of ['pnpm', 'bun', 'uv', 'pip'] as const) {
      const r = await rowOf(body, 'merge', 'licences', { services: [svc('.', { packageManager, language: packageManager === 'uv' || packageManager === 'pip' ? 'python' : 'node' })] });
      expect(r.status, packageManager).toBe('partial');
      expect(r.why, packageManager).toMatch(/installed/);
    }
    // npm's package-lock.json carries the licences itself: covered
    expect((await rowOf(body, 'merge', 'licences')).status).toBe('covered');
  });

  // Fix round 1 (ruling P50 I1, I2): only no severity filter, or one holding UNKNOWN, HIGH and CRITICAL, can be covered,
  // read with Trivy's own flag grammar; and only npm's package-lock.json carries licences without an install.
  it('coverage: a Trivy severity list must keep UNKNOWN, HIGH and CRITICAL, in every flag form (P50 I2)', async () => {
    neverOff.on = true;
    const pr = (cmd: string) => `on: pull_request\n${job(run(cmd))}`;
    const st = async (flags: string) => (await rowOf(pr(`trivy fs --scanners license ${flags} --exit-code 1 .`), 'merge', 'licences')).status;
    for (const f of ['--severity UNKNOWN', '--severity UNKNOWN,LOW,MEDIUM', '-sHIGH,CRITICAL', '-s HIGH,CRITICAL', '--severity=UNKNOWN,HIGH', '-s=CRITICAL',
      '--severity UNKNOWN,HIGH,CRITICAL --severity LOW', '--severity $SEV', '--severity']) {
      expect(await st(f), f).toBe('partial');
    }
    for (const f of ['', '--severity UNKNOWN,HIGH,CRITICAL', '-sUNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--severity=critical,high,unknown', '-s UNKNOWN,HIGH,CRITICAL']) {
      expect(await st(f), f).toBe('covered');
    }
    const act = (sev: string) => `on: pull_request\n${job(`      - uses: aquasecurity/trivy-action@76071ef0d7ec797419534a183b498b4d6366cf37\n        with:\n          scan-type: fs\n          scanners: license\n          exit-code: '1'\n          severity: '${sev}'\n`)}`;
    expect((await rowOf(act('UNKNOWN'), 'merge', 'licences')).status).toBe('partial');
    expect((await rowOf(act('UNKNOWN,HIGH,CRITICAL'), 'merge', 'licences')).status).toBe('covered');
  });

  it('coverage: only npm package-lock.json can make a Trivy licence scan covered; every other lockfile is partial (P50 I1)', async () => {
    neverOff.on = true;
    const body = `on: pull_request\n${job(run('trivy fs --scanners license --exit-code 1 .'))}`;
    for (const packageManager of ['yarn', 'poetry', 'pnpm', 'bun', 'uv', 'pip', undefined] as const) {
      const r = await rowOf(body, 'merge', 'licences', { services: [svc('.', { packageManager })] });
      expect(r.status, String(packageManager)).toBe('partial');
    }
    // a second service without a lockfile pipegen trusts makes it partial too
    expect((await rowOf(body, 'merge', 'licences', { services: [svc('.'), svc('tools', { language: 'other', packageManager: undefined })] })).status).toBe('partial');
    expect((await rowOf(body, 'merge', 'licences')).status).toBe('covered'); // npm alone
  });

  it('coverage: trivy fs --scanners vuln,license --exit-code 1 on pull_request → licences covered; without license → missing', async () => {
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    const pr = (cmd: string) => `on: pull_request\n${job(run(cmd))}`;
    expect(await rowOf(pr('trivy fs --scanners vuln,license --exit-code 1 .'), 'merge', 'licences')).toMatchObject({ status: 'covered', by: 'trivy-license' });
    expect(await rowOf(pr('trivy fs --scanners=license --exit-code 1 .'), 'merge', 'licences')).toMatchObject({ status: 'covered', by: 'trivy-license' });
    expect((await rowOf(pr('trivy fs --scanners vuln --exit-code 1 .'), 'merge', 'licences')).status).toBe('missing');
    expect((await rowOf(pr('trivy fs --exit-code 1 .'), 'merge', 'licences')).status).toBe('missing');
    expect((await rowOf(pr('trivy fs --scanners license .'), 'merge', 'licences')).status).toBe('partial'); // no --exit-code
    expect((await rowOf(pr('trivy fs --scanners license --scanners vuln --exit-code 1 .'), 'merge', 'licences')).status).toBe('missing'); // the last one wins
    expect((await rowOf(pr('echo trivy fs --scanners license --exit-code 1 .'), 'merge', 'licences')).status).toBe('missing');
    expect((await rowOf(pr('trivy config --scanners license --exit-code 1 .'), 'merge', 'licences')).status).toBe('missing');
    const action = (lines: string) => `on: pull_request\n${job(`      - uses: aquasecurity/trivy-action@0.33.1\n        with:\n${lines}`)}`;
    expect((await rowOf(action("          scan-type: fs\n          scanners: vuln,license\n          exit-code: '1'\n"), 'merge', 'licences')).status).toBe('covered');
    expect((await rowOf(action("          scan-type: fs\n          scanners: vuln\n          exit-code: '1'\n"), 'merge', 'licences')).status).toBe('missing');
    expect((await rowOf(action("          scanners: ${{ inputs.s }}\n          exit-code: '1'\n"), 'merge', 'licences')).status).toBe('missing');
  });

  it('coverage: dependency-review-action without allow/deny-licenses → licences missing', async () => {
    expect((await rowOf(ciUses('actions/dependency-review-action@v5'), 'merge', 'licences')).status).toBe('missing');
    expect((await rowOf(ciUses('actions/dependency-review-action@v5', "          allow-licenses: ''\n"), 'merge', 'licences')).status).toBe('missing');
    expect(await rowOf(ciUses('actions/dependency-review-action@v5', '          allow-licenses: MIT, Apache-2.0\n'), 'merge', 'licences')).toMatchObject({ status: 'covered', by: 'dependency-review-licences' });
    expect((await rowOf(ciUses('actions/dependency-review-action@v5', '          deny-licenses: GPL-3.0\n          license-check: false\n'), 'merge', 'licences')).status).toBe('missing');
    expect((await rowOf(ciUses('actions/dependency-review-action@v5', '          config-file: ./.github/dr.yml\n'), 'merge', 'licences')).status).toBe('partial');
    expect((await rowOf(ciUses('actions/dependency-review-action@v5', '          allow-licenses: MIT\n'), 'merge', 'licences', { private: true, ownerType: 'User' })).status).toBe('partial');
    for (const [cmd, want] of [['cargo deny check licenses', 'covered'], ['cargo deny check', 'partial'], ['cargo deny check advisories', 'missing'], ['grant check dir:.', 'covered'],
      ['grant check --dry-run dir:.', 'partial'], ['fossa test', 'partial']]) {
      expect((await rowOf(ciRun(cmd), 'merge', 'licences')).status, cmd).toBe(want);
    }
  });

  it('coverage: scorecard-action on schedule → covered; workflow_dispatch only → partial', async () => {
    const steps = job('      - uses: ossf/scorecard-action@v2.5.0\n        with:\n          results_file: r.sarif\n          results_format: sarif\n');
    expect(await rowOf(`on:\n  schedule:\n    - cron: '0 3 * * 1'\n${steps}`, 'merge', 'scorecard')).toMatchObject({ status: 'covered', by: 'scorecard' });
    expect((await rowOf(`on:\n  push:\n    branches: [main]\n${steps}`, 'merge', 'scorecard')).status).toBe('covered');
    const d = await rowOf(`on: workflow_dispatch\n${steps}`, 'merge', 'scorecard');
    expect(d).toMatchObject({ status: 'partial', by: 'scorecard' });
    expect(d.why).toMatch(/not on a schedule or on every push to the default branch/);
    expect((await rowOf(`on: pull_request\n${steps}`, 'merge', 'scorecard')).status).toBe('partial');
    expect((await rowOf(`on:\n  push:\n    branches: [main]\n    paths: [src/**]\n${steps}`, 'merge', 'scorecard')).status).toBe('partial');
    expect((await rowOf(`on:\n  push:\n    branches: [dev]\n${steps}`, 'merge', 'scorecard')).status).toBe('partial');
  });

  it('coverage: harden-runner block mode on a private repo → egress partial (DEC #80)', async () => {
    const rel = (withLines: string) => `on:\n  release:\n    types: [published]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: step-security/harden-runner@v2\n        with:\n${withLines}      - run: npm publish\n`;
    const over = { services: [svc('.', { scripts: ['start'] })] };
    const block = '          egress-policy: block\n          disable-sudo-and-containers: true\n';
    const r = await rowOf(rel(block), 'deploy', 'egress', { ...over, private: true }, 'app');
    expect(r).toMatchObject({ status: 'partial', by: 'harden-runner' });
    expect(r.why).toMatch(/private repo/);
    expect(await rowOf(rel(block), 'deploy', 'egress', over, 'app')).toMatchObject({ status: 'covered', by: 'harden-runner' }); // public
    // fix round 1 (E7, ruling P8): disable-sudo alone leaves docker, which is root-equivalent
    expect((await rowOf(rel('          egress-policy: block\n          disable-sudo: true\n'), 'deploy', 'egress', over, 'app')).status).toBe('partial');
    expect((await rowOf(rel('          egress-policy: block\n'), 'deploy', 'egress', over, 'app')).status).toBe('partial'); // sudo can undo it
    expect((await rowOf(rel('          disable-sudo-and-containers: true\n'), 'deploy', 'egress', over, 'app')).status).toBe('partial'); // block must be explicit
    expect((await rowOf(rel(`${block}          policy: my-policy\n`), 'deploy', 'egress', over, 'app')).status).toBe('partial'); // a stored policy replaces the inputs
  });

  it('coverage: bullfrog counts only with egress-policy block AND enable-sudo false (PB5)', async () => {
    const rel = (withLines: string, more = '') => `on:\n  release:\n    types: [published]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: bullfrogsec/bullfrog@v0.9.0\n        with:\n${withLines}      - run: npm publish\n${more}`;
    const over = { services: [svc('.', { scripts: ['start'] })] };
    const st = async (body: string, o: Partial<RepoProfile> = over) => (await rowOf(body, 'deploy', 'egress', o, 'app')).status;
    const good = '          egress-policy: block\n          enable-sudo: false\n';
    expect(await rowOf(rel(good), 'deploy', 'egress', over, 'app')).toMatchObject({ status: 'covered', by: 'bullfrog' });
    expect(await st(rel(good), { ...over, private: true })).toBe('covered'); // Bullfrog blocks on private repos too
    const partial = await rowOf(rel('          egress-policy: block\n'), 'deploy', 'egress', over, 'app');
    expect(partial).toMatchObject({ status: 'partial', by: 'bullfrog' });
    expect(partial.why).toMatch(/egress-policy set to block, enable-sudo set to false/);
    expect(await st(rel('          enable-sudo: false\n'))).toBe('partial'); // audit mode by default
    expect(await st(rel('          egress-policy: audit\n          enable-sudo: false\n'))).toBe('partial');
    expect(await st(rel('          egress-policy: ${{ inputs.p }}\n          enable-sudo: false\n'))).toBe('partial');
    expect(await st(rel(`${good}          EGRESS-POLICY: audit\n`))).toBe('partial'); // every spelling must hold
    // the control plane's policy replaces the inputs (the key name is built, so no redact rule matches this file)
    expect(await st(rel(`${good}          ${['api', 'token'].join('-')}: \${{ inputs.bf }}\n`))).toBe('partial');
    expect(await st(rel(good).replace('      - uses: bullfrogsec', '      - continue-on-error: true\n        uses: bullfrogsec'))).toBe('partial');
  });

  it('coverage: egress is covered only when every job of the release workflow starts with it (PB5)', async () => {
    const over = { services: [svc('.', { scripts: ['start'] })] };
    const bf = '      - uses: bullfrogsec/bullfrog@v0.9.0\n        with:\n          egress-policy: block\n          enable-sudo: false\n';
    const jobOf = (name: string, steps: string) => `  ${name}:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`;
    const wfOf = (...jobs: string[]) => `on:\n  release:\n    types: [published]\njobs:\n${jobs.join('')}`;
    const st = async (body: string) => {
      const r = await rowOf(body, 'deploy', 'egress', over, 'app');
      return r.status;
    };
    expect(await st(wfOf(jobOf('build', `${bf}${run('npm ci')}`), jobOf('publish', `${bf}${run('npm publish')}`)))).toBe('covered');
    const some = await rowOf(wfOf(jobOf('build', `${bf}${run('npm ci')}`), jobOf('publish', run('npm publish'))), 'deploy', 'egress', over, 'app');
    expect(some.status).toBe('partial');
    expect(some.why).toBe("Egress control runs in some release jobs only: .github/workflows/ci.yml (job publish) doesn't start with it, so its steps can reach any site.");
    expect(await st(wfOf(jobOf('publish', `${run('npm ci')}${bf}${run('npm publish')}`)))).toBe('partial'); // not the first step
    expect(await st(wfOf(jobOf('build', `${bf}${run('npm ci')}`), '  call:\n    uses: o/other/.github/workflows/x.yml@v1\n'))).toBe('unknown'); // never covered
    expect(await st(wfOf(jobOf('build', `${bf}${run('npm ci')}`), `  skipped:\n    if: false\n    runs-on: x\n    steps:\n${run('npm publish')}`))).toBe('covered'); // a job that never runs
    // a local composite action counts only when bullfrog is its own first step
    const dir = makeTempDir();
    writeIn(dir, '.github/actions/lock/action.yml', `runs:\n  using: composite\n  steps:\n    - run: echo setup\n      shell: bash\n${bf.replace(/^ {6}/gm, '    ')}`);
    writeIn(dir, '.github/actions/lock2/action.yml', `runs:\n  using: composite\n  steps:\n${bf.replace(/^ {6}/gm, '    ')}`);
    wf(dir, 'rel.yml', wfOf(jobOf('publish', `      - uses: ./.github/actions/lock\n${run('npm publish')}`)));
    expect(row(await cov(dir, over), 'deploy', 'egress', 'app').status).toBe('partial');
    const dir2 = makeTempDir();
    writeIn(dir2, '.github/actions/lock2/action.yml', `runs:\n  using: composite\n  steps:\n${bf.replace(/^ {6}/gm, '    ')}`);
    wf(dir2, 'rel.yml', wfOf(jobOf('publish', `      - uses: ./.github/actions/lock2\n${run('npm publish')}`)));
    expect(row(await cov(dir2, over), 'deploy', 'egress', 'app').status).toBe('covered');
    // a job whose egress step only holds under a condition doesn't count for the others
    expect(await st(wfOf(jobOf('build', `${bf}${run('npm ci')}`), jobOf('publish', `${bf.replace('      - uses:', "      - if: github.event_name == 'release'\n        uses:")}${run('npm publish')}`)))).toBe('partial');
  });

  it('coverage: pre-commit run --all-files with ruff-format and mypy hooks → format and type-check covered', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', [
      'repos:',
      '  - repo: https://github.com/astral-sh/ruff-pre-commit', '    rev: v0.6.0', '    hooks:', '      - id: ruff-format',
      '  - repo: https://github.com/pre-commit/mirrors-mypy', '    rev: v1.11.0', '    hooks:', '      - id: mypy',
      '  - repo: https://github.com/hadolint/hadolint', '    rev: v2.12.0', '    hooks:', '      - id: hadolint',
      '  - repo: https://github.com/rhysd/actionlint', '    rev: v1.7.1', '    hooks:', '      - id: actionlint',
    ].join('\n'));
    ci(dir, '      - uses: pre-commit/action@v3.0.1\n');
    const rows = await cov(dir, { services: [svc('.', { language: 'python', packageManager: 'uv', scripts: [], dockerfile: 'Dockerfile', quality: { ...q, pythonTyped: true } })] });
    expect(row(rows, 'merge', 'format', 'app')).toMatchObject({ status: 'covered', by: 'ruff-format' });
    expect(row(rows, 'merge', 'type-check', 'app')).toMatchObject({ status: 'covered', by: 'mypy' });
    expect(row(rows, 'merge', 'dockerfile-lint', 'app')).toMatchObject({ status: 'covered', by: 'hadolint' });
    expect(row(rows, 'merge', 'workflow-lint')).toMatchObject({ status: 'covered', by: 'actionlint' });
    expect(row(rows, 'merge', 'format', 'app').why).toMatch(/in the pre-commit hooks/);
  });

  it('coverage: formatter hooks carry format only into CI pre-commit runs, with their reasons (PS14)', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', 'repos:\n  - repo: https://github.com/psf/black-pre-commit-mirror\n    rev: 24.8.0\n    hooks:\n      - id: black\n        files: ^src/\n');
    ci(dir, run('pre-commit run --all-files'));
    expect(row(await cov(dir, { services: [pySvc] }), 'merge', 'format', 'app')).toMatchObject({ status: 'partial', by: 'black' });
    // SKIP naming the hook leaves it partial (P57 C4); a hook-stage run on staged files carries nothing
    const dir2 = makeTempDir();
    writeIn(dir2, '.pre-commit-config.yaml', 'repos:\n  - repo: https://github.com/psf/black-pre-commit-mirror\n    rev: 24.8.0\n    hooks:\n      - id: black\n');
    ci(dir2, run('SKIP=black pre-commit run --all-files'));
    expect(row(await cov(dir2, { services: [pySvc] }), 'merge', 'format', 'app').status).toBe('partial');
    const dir3 = makeTempDir();
    writeIn(dir3, '.pre-commit-config.yaml', 'repos:\n  - repo: https://github.com/psf/black-pre-commit-mirror\n    rev: 24.8.0\n    hooks:\n      - id: black\n');
    ci(dir3, run('pre-commit run'));
    expect(row(await cov(dir3, { services: [pySvc] }), 'merge', 'format', 'app').status).toBe('missing');
    // a lefthook formatter (stage_fixed re-stages) never covers format
    const dir4 = makeTempDir();
    writeIn(dir4, 'lefthook.yml', 'pre-commit:\n  commands:\n    fmt:\n      run: npx prettier --write {staged_files}\n      stage_fixed: true\n');
    ci(dir4, run('npx lefthook run pre-commit --all-files'));
    expect(row(await cov(dir4, { precommit: 'lefthook' }), 'merge', 'format', 'app').status).toBe('missing');
  });

  it('coverage: formatter hooks (adversarial): one that neither writes nor checks never carries format', async () => {
    const st = async (hooks: string) => {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', `repos:\n${hooks}`);
      ci(dir, run('pre-commit run --all-files'));
      // P57 (C1): prettier and biome format Node code, black Python
      const r = row(await cov(dir, /prettier|biome/.test(hooks) ? {} : { services: [pySvc] }), 'merge', 'format', 'app');
      return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
    };
    const local = (entry: string) => `  - repo: local\n    hooks:\n      - id: fmt\n        name: fmt\n        language: system\n        entry: ${entry}\n`;
    expect(await st(local('prettier'))).toBe('missing'); // prints the formatted text, writes nothing, exits 0
    expect(await st(local('npx prettier --write'))).toBe('covered prettier');
    expect(await st(local('prettier --check'))).toMatch(/^covered prettier/);
    const black = (args: string) => `  - repo: https://github.com/psf/black-pre-commit-mirror\n    rev: 24.8.0\n    hooks:\n      - id: black\n        args: ${args}\n`;
    expect(await st(black('[--diff]'))).toBe('missing'); // --diff alone only prints
    expect(await st(black('[--diff, --check]'))).toBe('covered black');
    expect(await st(black('[--line-length=100]'))).toBe('covered black');
    // a hook repo pipegen doesn't know stays partial (it may write), never covered
    expect(await st('  - repo: https://github.com/rbubley/mirrors-prettier\n    rev: v3.3.3\n    hooks:\n      - id: prettier\n')).toBe('partial prettier');
    expect(await st('  - repo: https://github.com/biomejs/pre-commit\n    rev: v2.0.0\n    hooks:\n      - id: biome-format\n        args: [--staged]\n')).toBe('missing');
  });

  it('coverage: docker:// steps match multi-word signatures by their args (trivy image)', async () => {
    const over = { services: [dockerSvc] };
    const img = (args: string) => ciUses('docker://aquasec/trivy:0.67.2', `          args: ${args}\n`);
    expect(await rowOf(img('image --exit-code 1 app:1'), 'merge', 'image-scan', over, 'app')).toMatchObject({ status: 'covered', by: 'trivy-image' });
    expect((await rowOf(img('config --exit-code 1 .'), 'merge', 'image-scan', over, 'app')).status).toBe('missing');
    expect((await rowOf(ciUses('docker://zricethezav/gitleaks:v8', '          args: version\n'), 'push', 'secrets')).status).toBe('missing');
  });

  it('coverage: go test -fuzz=FuzzX on schedule → fuzzing covered; go test alone doesn\'t', async () => {
    const over = { services: [svc('.', { language: 'go', quality: { ...q, fuzzTargets: true } })] };
    const sched = (cmd: string) => `on:\n  schedule:\n    - cron: '0 2 * * *'\n${job(run(cmd))}`;
    expect(await rowOf(sched('go test ./pkg -fuzz=FuzzX -fuzztime=10m'), 'merge', 'fuzzing', over, 'app')).toMatchObject({ status: 'covered', by: 'go-fuzz' });
    expect(await rowOf(sched('go test ./pkg -fuzz FuzzX'), 'merge', 'fuzzing', over, 'app')).toMatchObject({ status: 'covered', by: 'go-fuzz' });
    expect((await rowOf(sched('go test ./...'), 'merge', 'fuzzing', over, 'app')).status).toBe('missing');
    expect((await rowOf(sched('go test ./... -fuzz='), 'merge', 'fuzzing', over, 'app')).status).toBe('missing');
    expect((await rowOf(`on: pull_request\n${job(run('go test ./pkg -fuzz=FuzzX'))}`, 'merge', 'fuzzing', over, 'app')).status).toBe('partial');
    expect((await rowOf(`on:\n  schedule:\n    - cron: '0 2 * * *'\n${job('      - uses: google/clusterfuzzlite/actions/run_fuzzers@v1\n        with:\n          mode: batch\n')}`, 'merge', 'fuzzing', over, 'app')).status).toBe('covered');
    expect((await rowOf(`on:\n  schedule:\n    - cron: '0 2 * * *'\n${job('      - uses: google/clusterfuzzlite/actions/run_fuzzers@v1\n        with:\n          mode: coverage\n')}`, 'merge', 'fuzzing', over, 'app')).status).toBe('missing');
  });

  it('coverage: coverage runs are partial until a minimum is checked (PS17)', async () => {
    for (const [cmd, by] of [['npx vitest run --coverage', 'vitest-cov'], ['vitest --coverage.enabled', 'vitest-cov'], ['jest --coverage', 'jest-cov'], ['npx c8 mocha', 'c8'],
      ['nyc mocha', 'nyc'], ['pytest --cov=pkg', 'pytest-cov'], ['coverage report', 'coverage-py'], ['go test -coverprofile=c.out ./...', 'go-cover']]) {
      const r = await rowOf(ciRun(cmd), 'merge', 'coverage', langOver(cmd), 'app');
      expect(r, cmd).toMatchObject({ status: 'partial', by });
      // Plan P Task 4: vitest, jest and pytest runs are checked for a minimum (config-checks.test.ts); the others still aren't
      expect(r.why, cmd).toMatch(['vitest-cov', 'jest-cov', 'pytest-cov'].includes(by) ? /sets no minimum, so a drop can't fail the build/ : /hasn't checked for a minimum/);
    }
    for (const cmd of ['vitest run', 'vitest --coverage=false', 'vitest --coverage.enabled=false', 'jest', 'pytest --no-cov --cov=x', 'go test ./...']) {
      // Go is a stack pipegen doesn't support yet: a would-be missing row there is unknown
      expect((await rowOf(ciRun(cmd), 'merge', 'coverage', langOver(cmd), 'app')).status, cmd).toBe(cmd.startsWith('go ') ? 'unknown' : 'missing');
    }
  });

  it('coverage: own scripts count for the new categories through their text (PS11)', async () => {
    const dir = makeTempDir();
    pkg(dir, { typecheck: 'tsc --noEmit', 'format:check': 'prettier --check .', 'test:coverage': 'vitest run --coverage', knip: 'knip' });
    ci(dir, run('npm run typecheck') + run('npm run format:check') + run('npm run test:coverage') + run('npm run knip'));
    const rows = await cov(dir, { services: [tsSvc()] });
    expect(row(rows, 'merge', 'type-check', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run typecheck`' });
    expect(row(rows, 'merge', 'format', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run format:check`' });
    expect(row(rows, 'merge', 'coverage', 'app')).toMatchObject({ status: 'partial', by: 'your own `npm run test:coverage`' });
    expect(row(rows, 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run test:coverage`' });
    expect(row(rows, 'merge', 'dead-code', 'app')).toMatchObject({ status: 'covered', by: 'your own `npm run knip`' });
    const dir2 = makeTempDir();
    pkg(dir2, { typecheck: 'tsc --noEmit || true', format: 'prettier --write .' });
    ci(dir2, run('npm run typecheck') + run('npm run format'));
    const rows2 = await cov(dir2, { services: [tsSvc()] });
    expect(row(rows2, 'merge', 'type-check', 'app').status).toBe('partial');
    expect(row(rows2, 'merge', 'format', 'app').status).toBe('missing');
  });

  it('coverage: the other new tools: betterleaks, hadolint, kube-linter, conftest, schemathesis, zap-api, nuclei, jscpd', async () => {
    const st = async (body: string, layer: Layer, id: string, over: Partial<RepoProfile> = {}, service?: string) => {
      const r = await rowOf(body, layer, id, over, service);
      return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
    };
    expect(await st(ciRun('betterleaks git .'), 'merge', 'secrets')).toBe('covered betterleaks');
    expect(await st(ciRun('betterleaks dir . --exit-code=0'), 'merge', 'secrets')).toBe('partial betterleaks');
    expect(await st(ciRun('betterleaks version'), 'merge', 'secrets')).toBe('missing');
    const docker = { services: [dockerSvc] };
    expect(await st(ciRun('hadolint --no-fail Dockerfile'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('partial hadolint');
    expect(await st(ciRun('hadolint -t none Dockerfile'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('partial hadolint');
    expect(await st(ciRun('hadolint --failure-threshold=none Dockerfile'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('partial hadolint');
    expect(await st(ciUses('hadolint/hadolint-action@v3.1.0'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('covered hadolint');
    expect(await st(ciUses('hadolint/hadolint-action@v3.1.0', '          no-fail: true\n'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('partial hadolint');
    expect(await st(ciUses('hadolint/hadolint-action@v3.1.0', '          failure-threshold: ignore\n'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('partial hadolint');
    expect(await st(ciRun('docker run --rm -i hadolint/hadolint < Dockerfile'), 'merge', 'dockerfile-lint', docker, 'app')).toBe('covered hadolint');
    const k8s = { repoFiles: { ...emptyRepoFiles(), kubernetes: true } };
    expect(await st(ciRun('kube-linter lint k8s/'), 'merge', 'iac', k8s)).toBe('covered kube-linter');
    expect(await st(ciUses('stackrox/kube-linter-action@v1', '          directory: k8s\n'), 'merge', 'iac', k8s)).toBe('covered kube-linter');
    expect(await st(ciRun('conftest test k8s/'), 'merge', 'iac', k8s)).toBe('covered conftest');
    expect(await st(ciRun('conftest test --no-fail k8s/'), 'merge', 'iac', k8s)).toBe('partial conftest');
    expect(await st(ciRun('trivy config --exit-code 1 k8s/'), 'merge', 'iac', k8s)).toBe('covered trivy-config');
    const api = { services: [svc('.', { scripts: ['start'], quality: { ...q, apiSpec: { kind: 'file', path: 'openapi.yaml' } } })] };
    expect(await st(ciRun('st run openapi.yaml --url http://localhost:3000'), 'merge', 'api-dast', api, 'app')).toBe('covered schemathesis');
    expect(await st(ciUses('schemathesis/action@v2', '          schema: openapi.yaml\n'), 'merge', 'api-dast', api, 'app')).toBe('covered schemathesis');
    expect(await st(ciUses('zaproxy/action-api-scan@v0.10.0', '          target: openapi.yaml\n'), 'merge', 'api-dast', api, 'app')).toBe('partial zap-api');
    expect(await st(ciUses('zaproxy/action-api-scan@v0.10.0', '          target: openapi.yaml\n          fail_action: true\n'), 'merge', 'api-dast', api, 'app')).toBe('covered zap-api');
    expect(await st(ciRun('zap-api-scan.py -t openapi.yaml -f openapi -I'), 'merge', 'api-dast', api, 'app')).toBe('partial zap-api');
    expect(await st(ciRun('nuclei -u http://localhost:3000'), 'merge', 'dast', runnable, 'app')).toBe('partial nuclei');
    expect(await st(ciUses('projectdiscovery/nuclei-action@v3', '          args: -u http://localhost:3000\n'), 'merge', 'dast', runnable, 'app')).toBe('partial nuclei');
    expect(await st(ciRun('npx jscpd src'), 'merge', 'duplication')).toBe('covered jscpd'); // a warning check: running is enough
  });

  it('coverage: onlyWithFlags now uses the flag prefix rule, and a false value never counts (PS12)', async () => {
    const pkgService = { services: [svc('.', { publishedPackage: true })] };
    const st = async (cmd: string) => (await rowOf(`on:\n  release:\n    types: [published]\n${job(run(cmd))}`, 'deploy', 'attestation', pkgService, 'app')).status;
    expect(await st('npm publish --provenance')).toBe('covered');
    expect(await st('npm publish --provenance=true')).toBe('covered');
    for (const cmd of ['npm publish --provenance=0', 'npm publish --provenance=null', 'npm publish --provenance=false', 'npm publish --provenance=FALSE', 'npm publish --provenance=']) {
      expect(await st(cmd), cmd).toBe('missing');
    }
  });

  it('coverage: a command with more words than pipegen reads is partial, never covered (soft flags past the cap)', async () => {
    const files = Array.from({ length: 70 }, (_, i) => `f${i}.env`).join(' ');
    expect((await rowOf(ciRun(`gitleaks dir ${files} --exit-code=0`), 'push', 'secrets')).status).toBe('partial');
    expect((await rowOf(ciRun(`gitleaks dir ${files}`), 'push', 'secrets')).status).toBe('partial');
    expect((await rowOf(ciRun('gitleaks dir a b c'), 'push', 'secrets')).status).toBe('covered');
  });

  it('signatures: every entry that sets a fail field has a source comment (PS18: every entry Plan P adds or extends)', () => {
    const PLAN_P_IDS = [
      'betterleaks', 'biome', 'biome-ci', 'biome-format-check', 'prettier-check', 'ruff-format-check', 'black-check', 'gofmt-diff', 'gofmt-list', 'golangci-lint',
      'golangci-lint-fmt', 'oxlint', 'oxlint-type-check', 'tsc', 'mypy', 'pyright', 'basedpyright', 'vitest-cov', 'jest-cov', 'c8', 'nyc', 'pytest-cov', 'coverage-py',
      'go-cover', 'knip', 'creosote', 'deptry', 'vulture', 'go-mod-tidy', 'jscpd', 'hadolint', 'trivy-dockerfile', 'actionlint', 'zizmor', 'poutine', 'ghalint',
      'pinact', 'ratchet', 'zizmor-pins', 'dependency-review', 'dependency-review-licences', 'osv-pr-diff', 'trivy-license', 'cargo-deny-licences', 'cargo-deny',
      'grant', 'fossa', 'schemathesis', 'zap', 'zap-api', 'nuclei', 'kube-linter', 'conftest', 'bullfrog', 'harden-runner', 'scorecard', 'go-fuzz', 'fuzz-actions',
      'trivy-image', 'trivy-fs', 'trivy-config', 'grype', 'grype-image', 'scorecard-cli',
    ];
    const text = readFileSync(join(import.meta.dirname, '..', 'data', 'tool-signatures.yml'), 'utf8').split('\n');
    const ids = loadToolSignatures().map((t) => t.id);
    for (const id of PLAN_P_IDS) {
      expect(ids, id).toContain(id);
      const at = text.findIndex((l) => l === `  - id: ${id}`);
      const above: string[] = [];
      for (let i = at - 1; i >= 0 && (text[i] as string).trimStart().startsWith('#'); i--) above.push(text[i] as string);
      expect(above.some((l) => /https:\/\/\S+/.test(l)), `${id} has no source URL comment above it`).toBe(true);
    }
  });
});

// ---------- Plan P Task 3 fix round 1: the adversarial review's false "covered" (task-3-review.md) and ruling P8 ----------

describe('mapCoverage (Plan P Task 3 fix round 1)', () => {
  const q = emptyServiceQuality();
  const app = svc('.', { scripts: ['test', 'lint', 'start'], dockerfile: 'Dockerfile', quality: { ...q, tsconfig: true, fuzzTargets: true } });
  const base: Partial<RepoProfile> = { services: [app], repoFiles: { ...emptyRepoFiles(), kubernetes: true } };
  /** The row's status and `by` for a repo of these files (workflows read from disk). */
  async function st(files: Record<string, string>, layer: Layer, cat: string, over: Partial<RepoProfile> = {}, capabilities: Capabilities | null = caps): Promise<string> {
    const dir = makeTempDir();
    for (const [f, body] of Object.entries(files)) writeIn(dir, f, body);
    const p = await profileOf(dir, { ...base, ...over });
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir, capabilities === null ? {} : { capabilities });
    const r = rows.filter((x) => x.need.layer === layer && x.need.category === cat);
    if (r.length === 0) throw new Error(`no ${cat} row in ${layer}`);
    return r.map((x) => `${x.status}${x.by === undefined ? '' : ` ${x.by}`}`).join(' | ');
  }
  const both2 = 'on: [push, pull_request]\n';
  const jobOf = (steps: string, name = 'j', extra = '', runsOn = 'ubuntu-latest') => `  ${name}:\n    runs-on: ${runsOn}\n${extra}    steps:\n${steps}`;
  const wfile = (body: string, more: Record<string, string> = {}) => ({ '.github/workflows/ci.yml': body, ...more });
  const relOn = 'on:\n  release:\n';
  const bfStep = (more = '') => `      - uses: bullfrogsec/bullfrog@v0.9.0\n        with:\n          egress-policy: block\n          enable-sudo: false\n${more}`;
  const hrStep = (more = '', sudo = '          disable-sudo-and-containers: true\n') =>
    `      - uses: step-security/harden-runner@v2\n        with:\n          egress-policy: block\n${sudo}${more}`;
  const ci1 = (steps: string, extra = '') => wfile(`${both2}jobs:\n${jobOf(steps, 'j', extra)}`);

  it('fix round 1 (E1–E9): egress needs a working step on a supported runner in every release job of every release workflow', async () => {
    const rel = (steps: string, extra = '', runsOn = 'ubuntu-latest') => wfile(`${relOn}jobs:\n${jobOf(steps + run('npm publish'), 'j', extra, runsOn)}`);
    expect(await st(rel(bfStep()), 'deploy', 'egress')).toBe('covered bullfrog');
    expect(await st(rel(bfStep('          _dry-run-print-config: true\n')), 'deploy', 'egress')).toBe('partial bullfrog'); // E1: returns before the agent starts
    expect(await st(rel(bfStep('          dns-policy: any\n')), 'deploy', 'egress')).toBe('partial bullfrog'); // E2
    expect(await st(rel(bfStep('          dns-policy: allowed-domains-only\n')), 'deploy', 'egress')).toBe('covered bullfrog');
    expect(await st(rel(hrStep(), '    container: node:22\n'), 'deploy', 'egress')).toBe('partial harden-runner'); // E3
    expect(await st(rel(hrStep(), '', 'ubuntu-slim'), 'deploy', 'egress')).toBe('partial harden-runner'); // E4
    expect(await st(rel(hrStep(), '', '[self-hosted, linux]'), 'deploy', 'egress')).toBe('partial harden-runner'); // E5
    expect(await st(rel(hrStep(), '', '${{ matrix.os }}'), 'deploy', 'egress')).toBe('partial harden-runner');
    expect(await st(rel(bfStep(), '    container: node:22\n'), 'deploy', 'egress')).toBe('partial bullfrog'); // E6
    expect(await st(rel(bfStep(), '', 'ubuntu-slim'), 'deploy', 'egress')).toBe('covered bullfrog'); // Bullfrog's README lists ubuntu-slim
    expect(await st(rel(hrStep()), 'deploy', 'egress')).toBe('covered harden-runner');
    expect(await st(rel(hrStep('', '          disable-sudo: true\n')), 'deploy', 'egress')).toBe('partial harden-runner'); // E7
    // E8: egress in a CI workflow that doesn't release never counts
    expect(await st(wfile(`on:\n  push:\n    branches: [main]\n  pull_request:\njobs:\n${jobOf(bfStep() + run('npm test'))}`,
      { '.github/workflows/release.yml': `on:\n  push:\n    tags: ['v*']\njobs:\n${jobOf(run('npm publish'))}` }), 'deploy', 'egress')).toBe('missing');
    // E9: a second release workflow without egress lowers the row, and the why names its job
    const dir = makeTempDir();
    writeIn(dir, '.github/workflows/a.yml', `${relOn}jobs:\n${jobOf(bfStep() + run('npm publish'))}`);
    writeIn(dir, '.github/workflows/b.yml', `${relOn}jobs:\n${jobOf(run('npm publish --tag next'), 'next')}`);
    const p = await profileOf(dir, base);
    const r = row(await mapCoverage(p, floorNeeds(p, caps), dir, { capabilities: caps }), 'deploy', 'egress', 'app');
    expect(r).toMatchObject({ status: 'partial', by: 'bullfrog' });
    expect(r.why).toBe("Egress control runs in some release jobs only: .github/workflows/b.yml (job next) doesn't start with it, so its steps can reach any site.");
  });

  it('fix round 1 (T1, T8, L1, S1, T1c, W3): exit codes read the way the tools parse them, and a false fail flag never fails', async () => {
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    for (const cmd of ['trivy image --exit-code=00 app:1', 'trivy image --exit-code 0x0 app:1', 'trivy image --exit-code=+0 app:1', 'trivy image --exit-code 0o0 app:1',
      'trivy image --exit-code 256 app:1', 'trivy image --exit-code=-0 app:1']) {
      expect(await st(ci1(run(cmd)), 'merge', 'image-scan'), cmd).toBe('partial trivy-image');
    }
    expect(await st(ci1(run('trivy image --exit-code 2 app:1')), 'merge', 'image-scan')).toBe('covered trivy-image');
    expect(await st(ci1(run('trivy fs --exit-code=+0 .')), 'merge', 'deps')).toBe('partial trivy-fs');
    expect(await st(ci1(run('trivy fs --scanners vuln,license --exit-code=00 .')), 'merge', 'licences')).toBe('partial trivy-license');
    expect(await st(ci1(run('betterleaks git --exit-code=00 .')), 'merge', 'secrets')).toBe('partial betterleaks');
    expect(await st(ci1(run('gitleaks detect --exit-code 0x0')), 'merge', 'secrets')).toBe('partial gitleaks');
    expect(await st(ci1("      - uses: aquasecurity/trivy-action@0.33.1\n        with:\n          image-ref: app:1\n          exit-code: '00'\n"), 'merge', 'image-scan')).toBe('partial trivy-image');
    expect(await st(ci1("      - uses: aquasecurity/trivy-action@0.33.1\n        with:\n          image-ref: app:1\n          exit-code: '1'\n"), 'merge', 'image-scan')).toBe('covered trivy-image');
    expect(await st(ci1(run('poutine analyze_local . --fail-on-violation=false')), 'merge', 'workflow-lint')).toBe('partial poutine');
    expect(await st(ci1(run('trufflehog git file://. --fail=false')), 'merge', 'secrets')).toBe('partial trufflehog');
  });

  it('fix round 1 (T2, T3–T5, T7, H2–H4, ruling P8): download-only runs, soft env vars and auto-loaded config files', async () => {
    expect(await st(ci1(run('trivy image --download-db-only --exit-code 1 app:1')), 'merge', 'image-scan')).toBe('missing'); // T2
    expect(await st(ci1(run('trivy image --exit-code 1 app:1'), '    env:\n      TRIVY_SCANNERS: secret\n'), 'merge', 'image-scan')).toBe('partial trivy-image'); // T3
    expect(await st(ci1("      - uses: aquasecurity/trivy-action@0.33.1\n        env:\n          TRIVY_DOWNLOAD_DB_ONLY: 'true'\n        with:\n          image-ref: app:1\n          exit-code: '1'\n"),
      'merge', 'image-scan')).toBe('partial trivy-image'); // T3b
    expect(await st(ci1(run('TRIVY_EXIT_CODE=0 trivy image --exit-code 1 app:1')), 'merge', 'image-scan')).toBe('partial trivy-image'); // T7: presence is enough
    expect(await st(ci1(run('echo "TRIVY_SCANNERS=secret" >> "$GITHUB_ENV"') + run('trivy image --exit-code 1 app:1')), 'merge', 'image-scan')).toBe('partial trivy-image');
    expect(await st(wfile(`${both2}env: \${{ fromJSON(inputs.env) }}\njobs:\n${jobOf(run('trivy image --exit-code 1 app:1'))}`), 'merge', 'image-scan')).toBe('partial trivy-image');
    const repoTrivy = { 'trivy.yaml': 'scan:\n  scanners: [secret]\n' };
    expect(await st({ ...ci1(run('trivy image --exit-code 1 app:1')), ...repoTrivy }, 'merge', 'image-scan')).toBe('partial trivy-image'); // T4
    expect(await st({ ...ci1("      - uses: aquasecurity/trivy-action@0.33.1\n        with:\n          image-ref: app:1\n          exit-code: '1'\n"), ...repoTrivy }, 'merge', 'image-scan')).toBe('partial trivy-image'); // T5
    expect(await st({ ...ci1(run("trivy image --config '' --exit-code 1 app:1")), ...repoTrivy }, 'merge', 'image-scan')).toBe('covered trivy-image'); // --config '' lifts it
    expect(await st({ ...ci1(run('cd api && trivy fs --exit-code 1 .')), 'api/trivy.yaml': 'x: 1\n' }, 'merge', 'deps', { services: [app, svc('api')] }, caps)).toBe('missing | partial trivy-fs'); // app: none; api: its trivy.yaml
    // the file only counts in the run's folder or the repo root
    expect(await st({ ...ci1(run('trivy image --exit-code 1 app:1')), 'other/trivy.yaml': 'x: 1\n' }, 'merge', 'image-scan')).toBe('covered trivy-image');
    const docker = { Dockerfile: 'FROM alpine\n' };
    expect(await st({ ...ci1(run('hadolint Dockerfile'), '    env:\n      HADOLINT_NOFAIL: 1\n'), ...docker }, 'merge', 'dockerfile-lint')).toBe('partial hadolint'); // H2
    expect(await st({ ...ci1(run('hadolint Dockerfile')), ...docker, '.hadolint.yaml': 'no-fail: true\n' }, 'merge', 'dockerfile-lint')).toBe('partial hadolint'); // H3
    expect(await st({ ...ci1('      - uses: hadolint/hadolint-action@v3.1.0\n'), ...docker, '.hadolint.yml': 'failure-threshold: none\n' }, 'merge', 'dockerfile-lint')).toBe('partial hadolint'); // H4
    expect(await st({ ...ci1(run('hadolint -tnone Dockerfile')), ...docker }, 'merge', 'dockerfile-lint')).toBe('partial hadolint'); // H1
    // rule and ignore files stay in the ESLint class (ruling P8)
    expect(await st({ ...ci1(run('trivy image --exit-code 1 app:1')), '.trivyignore': 'CVE-1\n' }, 'merge', 'image-scan')).toBe('covered trivy-image');
    expect(await st({ ...ci1(run('grype dir:. --fail-on high')), '.grype.yaml': 'ignore: []\n' }, 'push', 'deps')).toBe('covered grype');
    expect(await st({ ...ci1(run('npx biome ci')), 'biome.json': '{"formatter":{"enabled":false}}' }, 'merge', 'format')).toBe('covered biome-ci');
    expect(await st({ ...ci1(run('zizmor .')), 'zizmor.yml': 'rules: {}\n' }, 'merge', 'workflow-lint')).toBe('covered zizmor');
    // a pre-commit hook in CI sees the job env (and the repo's config file)
    const hookCfg = { ...docker, '.pre-commit-config.yaml': 'repos:\n  - repo: https://github.com/hadolint/hadolint\n    rev: v2.12.0\n    hooks:\n      - id: hadolint\n' };
    expect(await st({ ...ci1(run('pre-commit run --all-files')), ...hookCfg }, 'merge', 'dockerfile-lint')).toBe('covered hadolint');
    expect(await st({ ...ci1(run('pre-commit run --all-files'), '    env:\n      HADOLINT_NOFAIL: 1\n'), ...hookCfg }, 'merge', 'dockerfile-lint')).toBe('partial hadolint');
    expect(await st({ ...ci1(run('pre-commit run --all-files')), ...hookCfg, '.hadolint.yaml': 'no-fail: true\n' }, 'merge', 'dockerfile-lint')).toBe('partial hadolint');
    expect(await st({ ...ci1(run('pre-commit run --all-files')), ...docker, '.pre-commit-config.yaml': 'repos:\n  - repo: https://github.com/hadolint/hadolint\n    rev: v2.12.0\n    hooks:\n      - id: hadolint\n        args: [-tnone]\n' },
      'merge', 'dockerfile-lint')).toBe('partial hadolint'); // PC3
    // an own script counts only for the own-script categories, so a scanner in one never covers image-scan
    expect(await st({ ...ci1(run('npm run scan')), 'package.json': JSON.stringify({ scripts: { scan: 'trivy image --exit-code 1 app:1' } }) },
      'merge', 'image-scan')).toBe('missing');
  });

  it('fix round 1 (G1, G2): a grype flag value is never the scan target; a real image scan still counts', async () => {
    expect(await st(ci1(run('grype src --distro alpine:3.19 --fail-on high')), 'merge', 'image-scan')).toBe('partial grype-image');
    expect(await st(ci1(run('grype app:1 --fail-on high --file ./r.json')), 'merge', 'image-scan')).toBe('covered grype-image');
    expect(await st(ci1(run('grype app:1 --fail-on high --file ./r.json')), 'merge', 'deps')).toBe('missing');
    expect(await st(ci1(run('grype -o json ghcr.io/o/app:1.2 --fail-on high')), 'merge', 'image-scan')).toBe('covered grype-image');
    expect(await st(ci1(run('grype --unknown-flag ghcr.io/o/app:1.2 --fail-on high')), 'merge', 'image-scan')).toBe('partial grype-image');
    expect(await st(ci1(run('grype dir:. --name app:1 --fail-on high')), 'merge', 'image-scan')).toBe('missing');
  });

  it('fix round 1 (C1–C6, W1, W2, P1, P2, F1): run-nothing spellings', async () => {
    for (const cmd of ['tsc --nocheck', 'tsc -noCheck', 'tsc -version', 'tsc -?', 'tsc --showconfig', 'tsc --listfilesonly', 'vue-tsc --NOCHECK', 'tsgo -listFilesOnly', 'tsc -W']) {
      expect(await st(ci1(run(cmd)), 'merge', 'type-check'), cmd).toBe('missing');
    }
    expect(await st(ci1(run('tsc -p tsconfig.json --noEmit')), 'merge', 'type-check')).toBe('covered tsc');
    for (const cmd of ['actionlint -version', 'actionlint -init-config', 'actionlint -help']) expect(await st(ci1(run(cmd)), 'merge', 'workflow-lint'), cmd).toBe('missing');
    for (const cmd of ['prettier --check --support-info', 'prettier --check --find-config-path x.js', 'prettier -c --file-info x.js']) {
      expect(await st(ci1(run(cmd)), 'merge', 'format'), cmd).toBe('missing');
    }
    expect(await st(ci1(run('ruff format --check --stdin-filename x.py')), 'merge', 'format')).toBe('missing');
    const sched = (cmd: string) => wfile(`on:\n  schedule:\n    - cron: '1 1 * * 1'\njobs:\n${jobOf(run(cmd))}`);
    expect(await st(sched('go test -list . -fuzz=FuzzX ./pkg'), 'merge', 'fuzzing')).toBe('missing');
    expect(await st(ci1(run('go test -list . ./...')), 'merge', 'unit-tests')).toBe('missing');
  });

  it('fix round 1 (D4, SC2, SC3): refs, a schedule that never fires, scorecard of another repo', async () => {
    const dra = (lines: string) => wfile(`on: pull_request\njobs:\n${jobOf(`      - uses: actions/dependency-review-action@v5\n${lines}`)}`);
    expect(await st(dra('        with:\n          base-ref: main\n          head-ref: main\n'), 'merge', 'dependency-review')).toBe('partial dependency-review');
    expect(await st(dra(''), 'merge', 'dependency-review')).toBe('covered dependency-review');
    const sc = (cron: string) => wfile(`on:\n  schedule:\n    - cron: '${cron}'\njobs:\n${jobOf('      - uses: ossf/scorecard-action@v2.5.0\n')}`);
    expect(await st(sc('0 0 31 2 *'), 'merge', 'scorecard')).toBe('partial scorecard');
    expect(await st(sc('0 0 30 2,4 *'), 'merge', 'scorecard')).toBe('covered scorecard'); // April 30 exists
    expect(await st(sc('0 0 31 apr,jun *'), 'merge', 'scorecard')).toBe('partial scorecard');
    expect(await st(sc('0 0 31 2 1'), 'merge', 'scorecard')).toBe('covered scorecard'); // a weekday restriction: it fires on Mondays
    const cli = (cmd: string) => wfile(`on:\n  schedule:\n    - cron: '1 1 * * 1'\njobs:\n${jobOf(run(cmd))}`);
    expect(await st(cli('scorecard --repo=github.com/kubernetes/kubernetes'), 'merge', 'scorecard')).toBe('missing');
    expect(await st(cli('scorecard --local .'), 'merge', 'scorecard')).toBe('covered scorecard-cli');
  });

  it('fix round 2 (N1b, N1c, N1f, N2, N2c, N2d): soft env and config files set where pipegen can only see the name', async () => {
    const t = run('trivy image --exit-code 1 app:1');
    expect(await st(ci1("      - run: |\n          {\n            echo 'TRIVY_SCANNERS<<EOF'\n            echo secret\n            echo EOF\n          } >> \"$GITHUB_ENV\"\n" + t), 'merge', 'image-scan'))
      .toBe('partial trivy-image'); // N1b: a GITHUB_ENV heredoc
    expect(await st(ci1(run('echo "TRIVY_SCANNERS"=secret >> $GITHUB_ENV') + t), 'merge', 'image-scan')).toBe('partial trivy-image'); // N1c
    expect(await st(ci1('      - uses: o/setenv@v1\n' + t), 'merge', 'image-scan')).toBe('unknown o/setenv@v1'); // N1f: the owner's own action (opaque)
    expect(await st(ci1('      - uses: docker://alpine:3.20\n' + t), 'merge', 'image-scan')).toBe('partial trivy-image'); // an image pipegen can't see into
    expect(await st(ci1('      - uses: docker://aquasec/trivy:0.67.2\n        with:\n          args: image --exit-code 1 app:1\n'), 'merge', 'image-scan'))
      .toBe('covered trivy-image'); // an image a signature names is that tool, not an opaque step
    expect(await st(ci1('      - uses: actions/checkout@v4\n' + t), 'merge', 'image-scan')).toBe('covered trivy-image'); // a third-party action: the SKIP limit
    expect(await st(ci1("      - run: |\n          printf 'scan:\\n  scanners: [secret]\\n' > trivy.yaml\n" + t), 'merge', 'image-scan')).toBe('partial trivy-image'); // N2c
    expect(await st({ ...ci1(run('cp ci/hl.yaml .hadolint.yaml') + run('hadolint Dockerfile')), Dockerfile: 'FROM alpine\n', 'ci/hl.yaml': 'no-fail: true\n' },
      'merge', 'dockerfile-lint')).toBe('partial hadolint'); // N2d
    // N2: another letter case counts only where the file system ignores it (macOS, Windows)
    expect(await st({ ...ci1(t), 'Trivy.yaml': 'x: 1\n' }, 'merge', 'image-scan')).toBe('covered trivy-image');
    expect(await st({ ...wfile(`${both2}jobs:\n${jobOf(t, 'j', '', 'macos-latest')}`), 'Trivy.yaml': 'x: 1\n' }, 'merge', 'image-scan')).toBe('partial trivy-image');
    expect(await st({ ...wfile(`${both2}jobs:\n${jobOf(run('hadolint Dockerfile'), 'j', '', 'windows-latest')}`), Dockerfile: 'FROM alpine\n', '.HADOLINT.yaml': 'no-fail: true\n' },
      'merge', 'dockerfile-lint')).toBe('partial hadolint');
    expect(await st({ ...wfile(`${both2}jobs:\n${jobOf(t, 'j', '', 'macos-latest')}`) }, 'merge', 'image-scan')).toBe('covered trivy-image');
  });

  it('fix round 2 (R4, R7): a padded exit code is a parse error (0); Go reads f as false', async () => {
    neverOff.on = true; // trivy-action as the vehicle for the input rules (P33)
    for (const code of ["' 1'", "'1 '", "'1.0'"]) {
      expect(await st(ci1(`      - uses: aquasecurity/trivy-action@0.33.1\n        with:\n          image-ref: app:1\n          exit-code: ${code}\n`), 'merge', 'image-scan'), code).toBe('partial trivy-image');
    }
    expect(await st(ci1('      - uses: aquasecurity/trivy-action@0.33.1\n        with:\n          image-ref: app:1\n          exit-code: 1\n'), 'merge', 'image-scan')).toBe('covered trivy-image');
    for (const v of ['f', 'F']) expect(await st(ci1(run(`poutine analyze_local . --fail-on-violation=${v}`)), 'merge', 'workflow-lint'), v).toBe('partial poutine');
  });

  it('fix round 2 (N4b–N4d, ruling P9): release workflows pipegen\'s readers miss still need egress', async () => {
    // flag and key names are built at runtime, so no redact rule matches this file
    const credFlagWord = `--${['tok', 'en'].join('')}`;
    const storeRef = (name: string) => `\${{ ${['secrets', name].join('.')} }}`;
    const idWrite = `${['id', 'token'].join('-')}: write`;
    const guarded = { '.github/workflows/release.yml': `${relOn}jobs:\n${jobOf(bfStep() + run('npm publish'))}` };
    const files = (more: Record<string, string>) => ({ ...guarded, ...more });
    expect(await st(guarded, 'deploy', 'egress')).toBe('covered bullfrog');
    // N4b: a caller of a local workflow that publishes
    expect(await st(files({ '.github/workflows/ci.yml': "on:\n  push:\n    tags: ['v*']\njobs:\n  p:\n    uses: ./.github/workflows/pub.yml\n",
      '.github/workflows/pub.yml': `on: workflow_call\njobs:\n${jobOf(run('npm publish'))}` }), 'deploy', 'egress')).toBe('partial bullfrog');
    // N4c: a deploy trigger and a secret other than GITHUB_TOKEN
    expect(await st(files({ '.github/workflows/ci.yml': `on:\n  push:\n    tags: ['v*']\njobs:\n${jobOf(run(`cargo publish ${credFlagWord} ${storeRef('CARGO_TOKEN')}`))}` }),
      'deploy', 'egress')).toBe('partial bullfrog');
    // N4d: a deploy trigger and an image push
    expect(await st(files({ '.github/workflows/build.yml': `on:\n  push:\n    branches: [main]\njobs:\n${jobOf('      - uses: docker/build-push-action@v6\n        with:\n          push: true\n          tags: ghcr.io/o/r:latest\n')}` }),
      'deploy', 'egress')).toBe('partial bullfrog');
    // a deploy trigger and a job that grants a write permission
    expect(await st(files({ '.github/workflows/b.yml': `on:\n  push:\n    branches: [main]\njobs:\n${jobOf(run('make release'), 'j', `    permissions:\n      ${idWrite}\n`)}` }),
      'deploy', 'egress')).toBe('partial bullfrog');
    // not a release: GITHUB_TOKEN only, no write grant, no push, or no deploy trigger
    expect(await st(files({ '.github/workflows/ci.yml': `on:\n  push:\n    branches: [main]\njobs:\n${jobOf(run(`gh api x ${credFlagWord} ${storeRef('GITHUB_TOKEN')}`))}` }),
      'deploy', 'egress')).toBe('covered bullfrog');
    expect(await st(files({ '.github/workflows/ci.yml': `on: pull_request\njobs:\n${jobOf(run('make x ${{ secrets.NPM_TOKEN }}'), 'j', '    permissions:\n      contents: write\n')}` }),
      'deploy', 'egress')).toBe('covered bullfrog');
    expect(await st(files({ '.github/workflows/build.yml': `on:\n  push:\n    branches: [main]\njobs:\n${jobOf('      - uses: docker/build-push-action@v6\n        with:\n          push: false\n')}` }),
      'deploy', 'egress')).toBe('covered bullfrog');
  });

  it('fix round 1 (perf): the release-wide egress pass and the config-file pass stay linear', async () => {
    const dir = makeTempDir();
    const bf20 = bfStep().repeat(20);
    for (let f = 0; f < 10; f++) {
      let body = `${relOn}jobs:\n`;
      for (let j = 0; j < 100; j++) body += `  j${j}:\n    runs-on: ubuntu-latest\n    steps:\n${j % 2 ? run('echo') : ''}${bf20}${run('npm publish')}${run('trivy image --exit-code 1 app:1')}`;
      writeIn(dir, `.github/workflows/w${f}.yml`, body);
    }
    writeIn(dir, 'trivy.yaml', 'x: 1\n');
    const p = await profileOf(dir, base);
    const t = performance.now();
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir, { capabilities: caps });
    expect(performance.now() - t).toBeLessThan(5000);
    expect(row(rows, 'deploy', 'egress', 'app').status).toBe('partial');
    expect(row(rows, 'merge', 'image-scan', 'app').status).toBe('partial');
  });
});

describe('mapCoverage (Plan P final review I1, ruling P33)', () => {
  const NEVER_WHY = /^The trivy-image check runs, but this action is on pipegen's never-use list \(76 of its 77 tags were force-pushed to malicious code in March 2026\); pin a reviewed alternative\.$/;
  const trivy = (uses: string, extra = '') => `${both}${job(`      - uses: ${uses}\n${extra}        with:\n          exit-code: '1'\n`)}`;

  it('P33: a never-listed action set up to fail is partial with a plain reason, never covered', async () => {
    const r = await one(trivy('aquasecurity/trivy-action@0.28.0'), 'merge', 'image-scan', runnable, 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(NEVER_WHY);
    // any letter case and a commit pin: the same never-list match the loader uses
    const r2 = await one(trivy(`AquaSecurity/Trivy-Action@${'a'.repeat(40)}`), 'merge', 'image-scan', runnable, 'app');
    expect(r2.status).toBe('partial');
    expect(r2.why).toMatch(NEVER_WHY);
  });

  it('P33: the never-list reason wins over continue-on-error and an if: condition', async () => {
    const coe = await one(trivy('aquasecurity/trivy-action@0.28.0', '        continue-on-error: true\n'), 'merge', 'image-scan', runnable, 'app');
    expect(coe.status).toBe('partial');
    expect(coe.why).toMatch(NEVER_WHY);
    const cond = await one(trivy('aquasecurity/trivy-action@0.28.0', "        if: github.event_name == 'push'\n"), 'merge', 'image-scan', runnable, 'app');
    expect(cond.status).toBe('partial');
    expect(cond.why).toMatch(NEVER_WHY);
  });

  it('P33: gitleaks-action (licence) and zizmor-action (beta) give their own plain reason', async () => {
    const g = await one(`${both}${job('      - uses: gitleaks/gitleaks-action@v2\n')}`, 'push', 'secrets');
    expect(g.status).toBe('partial');
    expect(g.why).toBe("The gitleaks check runs, but this action is on pipegen's never-use list (proprietary licence, needs a licence key and phones home); pin a reviewed alternative.");
    const z = await one(`${both}${job('      - uses: zizmorcore/zizmor-action@v0.2.0\n        with:\n          advanced-security: false\n')}`, 'merge', 'workflow-lint');
    expect(z.status).toBe('partial');
    expect(z.why).toBe("The zizmor check runs, but this action is on pipegen's never-use list (beta); pin a reviewed alternative.");
    // no internal document references leak into the report
    for (const w of [g.why, z.why]) expect(w).not.toMatch(/catalogue|DECISIONS|ruling/);
  });

  it('P33: a reviewed tool next to a never-listed one still covers the row', async () => {
    const body = `${both}${job("      - uses: gitleaks/gitleaks-action@v2\n      - run: gitleaks detect --exit-code 1\n")}`;
    expect((await one(body, 'push', 'secrets')).status).toBe('covered');
  });

  it('P33: an action not on the never-list is unchanged', async () => {
    const r = await one(`${both}${job("      - uses: anchore/scan-action@v6\n")}`, 'push', 'deps', {}, 'app');
    expect(r.status).toBe('covered');
  });
});

// DoD run 2026-10-29 (fastapi/full-stack-fastapi-template): backend tests run through repo shell scripts
// (`uv run bash scripts/tests-start.sh` → `bash scripts/test.sh` → `coverage run -m pytest`). The fixture is a minimal
// synthetic copy of that layout (test/fixtures/repos/workspaces-python-backend).
describe('coverage: repo shell script files (DoD fastapi)', () => {
  const fixtureProfile = async () => {
    const { makeRepo } = await import('./helpers/make-repo.js');
    const { readProject } = await import('../src/read/project.js');
    const dir = makeRepo('workspaces-python-backend', 'https://github.com/o/r.git');
    const p: RepoProfile = { ...(await readProject(dir)), private: false, ownerType: 'User', plan: 'free' };
    return { dir, p };
  };

  it('coverage: tests run by a script file the step calls, and the script it calls, count for that service', async () => {
    const { dir, p } = await fixtureProfile();
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir);
    const merge = row(rows, 'merge', 'unit-tests', 'app');
    expect(merge).toMatchObject({ status: 'covered', by: 'your own `scripts/tests-start.sh`', where: '.github/workflows/test-backend.yml (job test-backend)' });
    expect(row(rows, 'push', 'unit-tests', 'app').status).toBe('covered');
    // the frontend has no run of its own: still missing (a script in backend/ covers only backend)
    expect(row(rows, 'merge', 'unit-tests', 'frontend').status).toBe('missing');
  });

  it('coverage: a script file pipegen can\'t read is unknown, never missing; a script run under || true is partial', async () => {
    const { dir, p } = await fixtureProfile();
    const { rmSync } = await import('node:fs');
    rmSync(join(dir, 'backend/scripts/test.sh'));
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir);
    expect(row(rows, 'merge', 'unit-tests', 'app')).toMatchObject({ status: 'unknown', by: 'your own `scripts/tests-start.sh`' });
    expect(row(rows, 'merge', 'unit-tests', 'app').why).toMatch(/couldn't read/);

    const soft = await fixtureProfile();
    writeIn(soft.dir, '.github/workflows/test-backend.yml', `on: [push, pull_request]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash scripts/tests-start.sh || true\n        working-directory: backend\n`);
    const softRows = await mapCoverage(soft.p, floorNeeds(soft.p, caps), soft.dir);
    expect(row(softRows, 'merge', 'unit-tests', 'app').status).toBe('partial');
  });

  it('coverage: a script file is read without -e unless it sets it; a path that leaves the repo is never read', async () => {
    const { dir, p } = await fixtureProfile();
    writeIn(dir, 'backend/scripts/test.sh', '#!/usr/bin/env bash\npytest tests/\necho done\n'); // no set -e: pytest can't fail it
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir);
    expect(row(rows, 'merge', 'unit-tests', 'app').status).toBe('partial');
    writeIn(dir, 'backend/scripts/tests-start.sh', 'set -e\nbash ../../outside/test.sh\n');
    const out = await mapCoverage(p, floorNeeds(p, caps), dir);
    expect(row(out, 'merge', 'unit-tests', 'app').status).toBe('unknown'); // `..` is never followed: a script pipegen can't place (P50 I4)
  });

  it('coverage: `coverage run -m pytest` runs the tests; a flag whose value is the next word stops it', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job('      - run: coverage run --branch -m pytest tests/\n')}`);
    expect(row(await coverage(dir, pyApp), 'merge', 'unit-tests').status).toBe('covered');
    const odd = makeTempDir();
    wf(odd, 'ci.yml', `on: [push, pull_request]\n${job('      - run: coverage run --rcfile cfg -m pytest tests/\n')}`);
    expect(row(await coverage(odd, pyApp), 'merge', 'unit-tests').status).toBe('missing');
  });
});

// DoD run 2026-10-29 (spf13/cobra): Go read as language `other`, and "Unit tests" read "missing" though test.yml runs
// `make richtest` (go test). pipegen doesn't support Go (or any stack but Node and Python) yet, so a check that depends
// on the stack can't be called missing: it is unknown, saying why. The fixture is synthetic (test/fixtures/repos/go-module).
describe('coverage: stacks pipegen does not support yet (DoD cobra)', () => {
  const goProfile = async () => {
    const { makeRepo } = await import('./helpers/make-repo.js');
    const { readProject } = await import('../src/read/project.js');
    const dir = makeRepo('go-module', 'https://github.com/o/r.git');
    const p: RepoProfile = { ...(await readProject(dir)), private: false, ownerType: 'User', plan: 'free' };
    return { dir, p };
  };

  it('coverage: a Go check that would be missing is unknown "not supported yet"; a check pipegen really saw keeps its status', async () => {
    const { dir, p } = await goProfile();
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir);
    for (const id of ['unit-tests', 'sast', 'deps']) {
      const r = row(rows, 'merge', id, 'r');
      expect(r.status, id).toBe('unknown');
      expect(r.why, id).toMatch(/^pipegen doesn't support Go yet/);
    }
    expect(row(rows, 'merge', 'full-tests', 'r').status).toBe('unknown');
    expect(row(rows, 'pre-commit', 'format-lint', 'r').status).toBe('unknown');
    expect(row(rows, 'merge', 'lint', 'r')).toMatchObject({ status: 'covered', by: 'golangci-lint' }); // a real check stays covered
    // checks that don't depend on the stack are answered as usual
    expect(row(rows, 'merge', 'secrets').status).toBe('missing');
    expect(rows.some((r) => r.status === 'missing' && r.need.service !== undefined && !['image-build', 'image-scan', 'dast', 'sbom', 'signing', 'attestation', 'deploy-verify', 'dockerfile-lint', 'api-dast', 'egress', 'fuzzing'].includes(r.need.category))).toBe(false);
  });

  it('coverage: any language pipegen does not support gets the same rule (language other)', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job('      - run: cargo test\n')}`);
    const rows = await coverage(dir, { services: [svc('.', { language: 'other', packageManager: undefined, scripts: [] })] });
    expect(row(rows, 'merge', 'unit-tests')).toMatchObject({ status: 'unknown' });
    // P50 (M7): `other` may be a config-only image (nginx): the why doesn't claim a language
    expect(row(rows, 'merge', 'unit-tests').why).toMatch(/^pipegen can't tell this service's language, or doesn't support it yet/);
    // Node keeps "missing"
    const node = await coverage(makeTempDir());
    expect(row(node, 'merge', 'unit-tests').status).toBe('missing');
  });
});

// Fix round 1 of the DoD fixes (ruling P50; dod-fixes-review.md C1, C2, I4, M1): the reviewer's reproductions.
describe('coverage: repo shell script files, fix round 1 (P50)', () => {
  const steps = (...runs: string[]) => `${both}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n${runs.map((r) => run(r)).join('')}`;
  const mergeTests = async (dir: string, over: Partial<RepoProfile> = pyApp) => row(await coverage(dir, over), 'merge', 'unit-tests');
  const withScript = (body: string, files: Record<string, string> = { 'scripts/test.sh': 'set -e\npytest\n' }) => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', body);
    for (const [f, t] of Object.entries(files)) writeIn(dir, f, t);
    return dir;
  };

  it('C1: a script is followed only after allowlisted shell flags; -n, --noexec, -o noexec, -c or an unknown flag give no coverage', async () => {
    for (const cmd of ['bash -n scripts/test.sh', 'sh -n scripts/test.sh', 'bash --noexec scripts/test.sh', 'bash -o noexec scripts/test.sh', 'bash -en scripts/test.sh', 'bash --rcfile x scripts/test.sh', 'zsh -q scripts/test.sh']) {
      expect((await mergeTests(withScript(steps(cmd)))).status, cmd).toBe('missing');
    }
    for (const cmd of ['bash scripts/test.sh', 'bash -eux scripts/test.sh', 'bash -e -o pipefail scripts/test.sh', 'sh -x -- scripts/test.sh', 'bash +x -o errexit -o nounset -o xtrace -v scripts/test.sh']) {
      expect((await mergeTests(withScript(steps(cmd)))).status, cmd).toBe('covered');
    }
  });

  it('C1: `set -n` or `set -o noexec` in a script (any spelling) ends coverage from that line on', async () => {
    for (const s of ['set -n', 'set -en', 'set -o noexec', 'set -eo noexec', 'set -e -o noexec']) {
      expect((await mergeTests(withScript(steps('bash scripts/test.sh'), { 'scripts/test.sh': `set -e\n${s}\npytest\n` }))).status, s).toBe('missing');
    }
    // before it, a run still counts
    expect((await mergeTests(withScript(steps('bash scripts/test.sh'), { 'scripts/test.sh': 'set -e\npytest\nset -n\necho x\n' }))).status).toBe('covered');
  });

  it('C2: script files have their own read budget; a missing one makes the step unknown; package.json stays readable', async () => {
    // 310 missing scripts, then a `npm test` whose script does nothing: never covered (U23 still reads package.json)
    const many = Array.from({ length: 310 }, (_, i) => `bash scripts/m${i}.sh || true`);
    const dir = withScript(steps(...many, 'npm test'), { 'package.json': JSON.stringify({ name: 'app', scripts: { test: 'echo "Error: no test specified"' } }), 'package-lock.json': '{}' });
    expect((await mergeTests(dir, {})).status).not.toBe('covered');
    const only = withScript(steps('npm test'), { 'package.json': JSON.stringify({ name: 'app', scripts: { test: 'echo "Error: no test specified"' } }), 'package-lock.json': '{}' });
    expect((await mergeTests(only, {})).status).toBe('missing');
    // a script that runs the tests but comes after the budget is spent: unknown, never covered, never missing
    const files: Record<string, string> = { 'scripts/real.sh': 'set -e\npytest\n' };
    for (let i = 0; i < 130; i++) files[`scripts/e${i}.sh`] = 'echo hi\n';
    const spent = withScript(steps(...Array.from({ length: 130 }, (_, i) => `bash scripts/e${i}.sh`), 'bash scripts/real.sh'), files);
    const r = await mergeTests(spent);
    expect(r.status).toBe('unknown');
  });

  it('I4: a script pipegen can\'t place (cd "$(dirname "$0")", a variable in its path, a path outside the repo) is unknown, never missing', async () => {
    const dirname = withScript(steps('bash scripts/test.sh'), { 'scripts/test.sh': 'set -e\ncd "$(dirname "$0")/.."\nbash scripts/inner.sh\n', 'scripts/inner.sh': 'pytest\n' });
    expect((await mergeTests(dirname)).status).toBe('unknown');
    for (const cmd of ['bash "$DIR/test.sh"', 'bash ${GITHUB_WORKSPACE}/scripts/test.sh', 'bash ../outside/test.sh', 'bash /opt/ci/test.sh']) {
      expect((await mergeTests(withScript(steps(cmd)))).status, cmd).toBe('unknown');
    }
  });

  it('M1: a script run inside `docker run IMAGE` is the container\'s copy: unknown, not the host file', async () => {
    expect((await mergeTests(withScript(steps('docker run --rm python:3.14 bash scripts/test.sh')))).status).toBe('unknown');
  });
});

// Round 2 (ruling P51, review M2): in a followed script, a test that runs only under a condition is partial, saying so.
describe('coverage: conditions inside a followed script (P51)', () => {
  const st = async (script: string) => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n${run('bash scripts/test.sh')}`);
    writeIn(dir, 'scripts/test.sh', script);
    return row(await coverage(dir, pyApp), 'merge', 'unit-tests');
  };

  it('P51: a test run only inside if/case/while, after && or || on a test, or after a conditional exit is partial', async () => {
    for (const s of [
      'set -e\nif [ "$1" = ci ]; then\n  pytest\nfi\n',
      'set -e\ncase "$1" in\n  ci) pytest ;;\nesac\n',
      'set -e\nwhile false; do pytest; done\n',
      'set -e\n[ -n "$CI" ] && pytest\necho done\n', // P54: not the last command
      'set -e\ntest -z "$SKIP" || pytest\n',
      'set -e\n[ -n "$CI" ] && exit 0\npytest\n',
      'set -e\nif [ -n "$CI" ]; then exit 0; fi\npytest\n',
      'set -e\nf() { return 0; }\n[ -z "$X" ] || return 0\npytest\n',
    ]) {
      const r = await st(s);
      expect(r.status, s).toBe('partial');
      expect(r.why, s).toBe('Your own `scripts/test.sh` runs the check only under a condition in that script, so it may not run on every pull request.');
    }
  });

  it('P51: an unconditional run stays covered (also after a plain `cd x &&` and after a finished if block)', async () => {
    for (const s of ['set -e\npytest\n', 'set -e\ncd . && pytest\n', 'set -e\nif [ -n "$X" ]; then echo x; fi\npytest\n']) {
      expect((await st(s)).status, s).toBe('covered');
    }
  });
});

// Closing patch (ruling P52, dod-fixes-rereview-1.md N1, N2, m1, m2): allowlists, so the class of conditions closes.
describe('coverage: followed scripts and shells, allowlists (P52)', () => {
  const ci = (runLine: string, shell?: string) => `${both}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${runLine}\n${shell === undefined ? '' : `        shell: ${shell}\n`}`;
  const st = async (script: string, runLine = 'bash scripts/test.sh', shell?: string) => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', ci(runLine, shell));
    writeIn(dir, 'scripts/test.sh', script);
    return row(await coverage(dir, pyApp), 'merge', 'unit-tests');
  };
  const COND = 'Your own `scripts/test.sh` runs the check only under a condition in that script, so it may not run on every pull request.';

  it('(a) a test on an &&/|| chain is unconditional only after cd, pushd, export X=…, a literal allowlisted set, or source of a repo script', async () => {
    for (const s of ['command -v pytest >/dev/null && pytest', 'grep -q run ci.txt && pytest', 'make deps && pytest', 'true && pytest', 'f() { :; }\nf && pytest', '( cd . ) || pytest']) {
      const r = await st(`set -e\n${s}\necho done\n`); // P54: not the script's last command
      expect(r.status, s).toBe('partial');
      expect(r.why, s).toBe(COND);
    }
    for (const s of ['cd . && pytest', 'pushd . && pytest', 'export A=1 && pytest', 'set -eu && pytest', 'source scripts/env.sh && pytest', 'cd . && export A=1 && pytest']) {
      expect((await st(`set -e\n${s}\n`)).status, s).toBe('covered');
    }
  });

  it('(b) after an exit/return that can run under any condition, in a loop over a non-literal list, or after a call to a function that exits: partial', async () => {
    for (const s of [
      'grep -q skip ci.txt && exit 0\npytest', '( [ -n "$CI" ] ) && exit 0\npytest', 'skip() { exit 0; }\n[ -n "$CI" ] && skip\npytest',
      'skip() { exit 0; }\nskip\npytest', '{ exit 0; }\npytest', 'cd . || exit\npytest', 'for t in $TESTS; do pytest "$t"; done', 'for t in $(ls tests); do pytest; done',
      'for t; do pytest; done', 'f() { return; }\nf\npytest',
    ]) {
      const r = await st(`set -e\n${s}\n`);
      expect(r.status, s).toBe('partial');
    }
    // a literal list runs; an exit with a literal non-zero code fails the run (never a silent pass); a finished if block
    // P59 (3): `pytest "$t"` names a path pipegen can't place (unknown), so the loop is checked with -k, whose value isn't a path
    for (const s of ['for t in unit api; do pytest -k "$t"; done', 'cd . || exit 1\npytest', 'if true; then echo x; fi\npytest', 'if [ -n "$X" ]; then echo x; fi\npytest']) {
      expect((await st(`set -e\n${s}\n`)).status, s).toBe('covered');
    }
  });

  it('(c) `set` with a non-literal argument ends coverage: later tests are unknown', async () => {
    for (const s of ['set -${flags}', 'set $OPTS', 'set "$@"', 'set -e `opts`']) {
      const r = await st(`set -e\n${s}\npytest\n`);
      expect(r.status, s).toBe('unknown');
    }
  });

  it('(d) the shell: of a step must be a known spec; a no-exec one runs nothing, an unknown one is unknown (never missing)', async () => {
    const dir = (shell: string) => { const d = makeTempDir(); wf(d, 'ci.yml', ci('pytest', shell)); return d; };
    // bash/sh told not to run the commands: nothing runs
    for (const sh of ['bash -n {0}', 'bash -o noexec {0}', 'sh -en {0}', 'bash -e -n {0}', 'bash -l -n {0}']) {
      expect(row(await coverage(dir(sh), pyApp), 'merge', 'unit-tests').status, sh).toBe('missing');
    }
    // a spec pipegen doesn't know: it can't tell what runs (re-review 2: never a false missing)
    for (const sh of ['perl {0}', 'bash -c {0}', 'node {0}', 'bash --posix {0}', 'zsh {0}', '/usrbash {0}', 'usr/bin/bash {0}', '/opt/bin/bash {0}']) {
      expect(row(await coverage(dir(sh), pyApp), 'merge', 'unit-tests').status, sh).toBe('unknown');
    }
    // known specs, including the login shells setup-miniconda/setup-micromamba tell users to write, and absolute paths
    for (const sh of ['bash', 'sh', 'bash --noprofile --norc -eo pipefail {0}', 'sh -e {0}', 'bash -e {0}', 'bash {0}', 'bash -el {0}', 'bash -l {0}', 'bash --login -e {0}', '/usr/bin/bash -e {0}', '/bin/sh {0}']) {
      expect(row(await coverage(dir(sh), pyApp), 'merge', 'unit-tests').status, sh).toBe('covered');
    }
  });

  it('(e) a script run directly needs a bash or sh shebang with allowlisted flags; anything else gives no coverage', async () => {
    for (const sb of ['#!/bin/bash -n', '#!/bin/true', '#!/usr/bin/env python3', '#!/usr/bin/env -S bash -n', '']) {
      expect((await st(`${sb}\nset -e\npytest\n`, './scripts/test.sh')).status, JSON.stringify(sb)).toBe('missing');
    }
    for (const sb of ['#!/bin/bash', '#!/usr/bin/env bash', '#!/bin/sh -e', '#! /usr/bin/env sh', '#!/bin/bash -eux']) {
      expect((await st(`${sb}\nset -e\npytest\n`, './scripts/test.sh')).status, sb).toBe('covered');
    }
    // run through a shell, the shebang doesn't matter
    expect((await st('#!/usr/bin/env python3\nset -e\npytest\n')).status).toBe('covered');
  });
});

// Ruling P53: a literal non-zero exit isn't conditional, a non-literal one is; the same condition rules (one analyzer)
// for workflow `run:` blocks and package.json scripts.
describe('coverage: one condition analyzer for scripts, steps and package scripts (P53)', () => {
  const script = async (body: string) => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n${run('bash scripts/test.sh')}`);
    writeIn(dir, 'scripts/test.sh', body);
    return row(await coverage(dir, pyApp), 'merge', 'unit-tests');
  };
  const step = async (runText: string, files: Record<string, string> = {}) => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n${runText.split('\n').map((l) => `          ${l}`).join('\n')}\n`);
    for (const [f, t] of Object.entries(files)) writeIn(dir, f, t);
    return row(await coverage(dir, langOver(`${runText}\n${Object.values(files).join('\n')}`)), 'merge', 'unit-tests');
  };

  it('(1) an exit with a literal non-zero code is not conditional; one with a code pipegen can\'t read is', async () => {
    for (const s of ['cd . || exit 1', 'cd . || exit 2', '[ -n "$X" ] && exit 3']) expect((await script(`set -e\n${s}\npytest\n`)).status, s).toBe('covered');
    for (const s of ['[ -n "$X" ] && exit $?', 'cd . || exit "$code"', '[ -n "$X" ] && exit ${RC:-0}', 'grep -q x f || exit $RC']) {
      expect((await script(`set -e\n${s}\npytest\n`)).status, s).toBe('partial');
    }
  });

  it('(2) workflow run: blocks follow the same rules; the old step rules still work', async () => {
    for (const s of ['[ -f pyproject.toml ] && pytest\necho done', 'command -v pytest && pytest\necho done', 'if [ -n "$RUN" ]; then pytest; fi', '[ -n "$CI" ] && exit 0\npytest', 'for t in $TESTS; do pytest "$t"; done']) {
      const r = await step(s);
      expect(r.status, s).toBe('partial');
      expect(r.why, s).toMatch(/only under a condition in its shell code/);
    }
    expect((await step('set $OPTS\npytest')).status).toBe('unknown');
    for (const s of ['cd . && pytest', 'pytest', 'export A=1 && pytest', 'cd . || exit 1\npytest']) expect((await step(s)).status, s).toBe('covered');
    expect((await step('pytest || true')).status).toBe('partial'); // the old rules still apply
  });

  it('(2) package.json script strings follow the same rules', async () => {
    const pkg = (test: string) => ({ 'package.json': JSON.stringify({ name: 'app', scripts: { test } }) });
    const r = await step('npm test', pkg('command -v jest || exit 0; jest')); // after a conditional exit (P54: not a last && chain)
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/only under a condition/);
    expect((await step('npm test', pkg('cd . && jest'))).status).toBe('covered');
    expect((await step('npm test', pkg('jest'))).status).toBe('covered');
  });

  it('(3) what the audit can\'t see names the shell tricks it doesn\'t model', async () => {
    const { CANT_SEE } = await import('../src/audit/render.js');
    expect(CANT_SEE.some((l) => /trap … EXIT/.test(l) && /alias/.test(l) && /function named like the test tool/.test(l))).toBe(true);
  });
});

// Ruling P54: an && chain whose exit status is the final status of the step, package script or followed script (its
// last command, no `||`, nothing conditional before it) is unconditional: an earlier failure fails the run visibly.
describe('coverage: the last && chain carries the run\'s status (P54)', () => {
  const step = async (runText: string, files: Record<string, string> = {}, id = 'unit-tests') => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n${runText.split('\n').map((l) => `          ${l}`).join('\n')}\n`);
    for (const [f, t] of Object.entries(files)) writeIn(dir, f, t);
    // a TypeScript service, so the type check is one of its needs; P57 (C1): a Python one for pytest
    const python = /\bpytest\b/.test(`${runText}\n${Object.values(files).join('\n')}`);
    return row(await coverage(dir, python ? pyApp : { services: [svc('.', { quality: { ...emptyServiceQuality(), tsconfig: true } })] }), 'merge', id);
  };
  const pkg = (test: string) => ({ 'package.json': JSON.stringify({ name: 'app', scripts: { test, build: 'tsc -p .' } }) });

  it('P54: ky\'s chain as the last command of its package script → type check covered; followed by another command → partial', async () => {
    expect((await step('npm test', pkg('xo && npm run build && tsc --project tsconfig.test.json && ava'), 'type-check')).status).toBe('covered');
    expect((await step('npm test', pkg('xo && npm run build && tsc --project tsconfig.test.json && ava; echo done'), 'type-check')).status).toBe('partial');
  });

  it('P54: in a step, the last && chain is covered; not last, with || anywhere, or after a conditional exit or loop, it is partial', async () => {
    expect((await step('[ -f x ] && pytest')).status).toBe('covered');
    expect((await step('echo start\ncommand -v pytest && pytest')).status).toBe('covered');
    for (const s of ['command -v pytest && pytest\necho done', '[ -f x ] || make && pytest', 'false || jest', '[ -n "$X" ] && exit 0\nmake && pytest',
      'for t in $T; do :; done\nmake && pytest', 'if [ -n "$X" ]; then make && pytest; fi', '{ make && pytest; }\necho x']) {
      expect((await step(s)).status, s).toBe('partial');
    }
  });

  it('P54: a followed script\'s last chain is covered only when the script\'s own call carries its status to the step', async () => {
    const s = { 'scripts/test.sh': 'set -e\necho prep\nlint && pytest\n' };
    expect((await step('bash scripts/test.sh', s)).status).toBe('covered');
    expect((await step('set -e\nbash scripts/test.sh\necho after', s)).status).toBe('covered'); // set -e on, a plain command
    expect((await step('if [ -n "$X" ]; then bash scripts/test.sh; fi', s)).status).toBe('partial');
    expect((await step('bash scripts/test.sh', { 'scripts/test.sh': 'lint && pytest\necho done\n' })).status).toBe('partial');
  });
});

// ---------- P57 (hand-check fixes review, fix round 1): every reproduction is a test, seen failing first ----------

describe('coverage: a tool covers only services of its languages (P57 C1)', () => {
  const backend = svc('backend', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...emptyServiceQuality(), pythonTyped: true } });
  const frontend = svc('frontend', { quality: { ...emptyServiceQuality(), tsconfig: true, versions: { typescript: '5.9.2' } } });
  const PRECOMMIT = 'repos:\n  - repo: https://github.com/pre-commit/mirrors-mypy\n    rev: v1.18.2\n    hooks:\n      - id: mypy\n'
    + '  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.16.0\n    hooks:\n      - id: ruff\n      - id: ruff-format\n';
  const rowsOf = async (steps: string, files: Record<string, string> = {}, services = [backend, frontend], precommit: RepoProfile['precommit'] = null) => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    return coverage(dir, { services, precommit, monorepo: 'folders' });
  };
  const st = (rows: Coverage[], layer: Layer, id: string, service: string) => {
    const r = row(rows, layer, id, service);
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };

  it('lang1 probe: a Python tool run at the root never covers the TypeScript frontend, and a TS tool never the Python backend', async () => {
    const cases: [string, string, string, string][] = [
      ['mypy .', 'type-check', 'frontend', 'backend'],
      ['ruff check .', 'lint', 'frontend', 'backend'],
      ['pytest', 'unit-tests', 'frontend', 'backend'],
      ['npx tsc --noEmit', 'type-check', 'backend', 'frontend'],
      ['npx eslint .', 'lint', 'backend', 'frontend'],
      ['npx vitest run', 'unit-tests', 'backend', 'frontend'],
    ];
    for (const [cmd, id, wrong, right] of cases) {
      const rows = await rowsOf(run(cmd));
      expect(st(rows, 'push', id, wrong), `${cmd} → ${wrong}`).toBe('missing');
      expect(row(rows, 'push', id, right).status, `${cmd} → ${right}`).toBe('covered');
    }
  });

  it('lang1 probe: prek/pre-commit --all-files carries mypy, ruff and ruff-format only to the Python service', async () => {
    for (const cmd of ['prek run --all-files', 'pre-commit run --all-files']) {
      const rows = await rowsOf(run(cmd), { '.pre-commit-config.yaml': PRECOMMIT });
      for (const id of ['type-check', 'lint', 'format']) {
        expect(st(rows, 'push', id, 'frontend'), `${cmd} ${id} frontend`).toBe('missing');
        expect(row(rows, 'push', id, 'backend').status, `${cmd} ${id} backend`).toBe('covered');
      }
    }
  });

  it('lang1 probe: the pre-commit layer\'s ruff hook is not the frontend\'s format and lint hook', async () => {
    const rows = await rowsOf('', { '.pre-commit-config.yaml': PRECOMMIT }, [backend, frontend], 'pre-commit');
    expect(st(rows, 'pre-commit', 'format-lint', 'frontend')).toBe('missing');
    expect(row(rows, 'pre-commit', 'format-lint', 'backend').status).toBe('covered');
  });

  it('a language-neutral tool (a secret scan, hadolint, trivy) still covers every service', async () => {
    const rows = await rowsOf(run('gitleaks git --exit-code 1') + run('hadolint backend/Dockerfile frontend/Dockerfile'));
    expect(row(rows, 'push', 'secrets').status).toBe('covered');
  });

  it('an own package script whose language pipegen can\'t tell (an unknown runner) is partial for a service of another language', async () => {
    const files = { 'package.json': JSON.stringify({ name: 'root', scripts: { test: 'node run-all-tests.js' } }) };
    const root = svc('.', { name: 'root' });
    const rows = await rowsOf(run('npm test'), files, [root, backend]);
    expect(row(rows, 'push', 'unit-tests', 'root').status).toBe('covered');
    expect(st(rows, 'push', 'unit-tests', 'backend')).toBe('partial your own `npm test`');
  });

  it('a tool given explicit path arguments covers only the services under those paths', async () => {
    const worker = svc('worker', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...emptyServiceQuality(), pythonTyped: true } });
    const tree = { 'backend/app.py': 'x = 1\n', 'worker/w.py': 'x = 1\n' };
    const rows = await rowsOf(run('mypy backend'), tree, [backend, worker, frontend]);
    expect(row(rows, 'push', 'type-check', 'backend').status).toBe('covered');
    expect(st(rows, 'push', 'type-check', 'worker')).toBe('missing');
    // a word that is no service folder (a subcommand, a file) keeps the run where it is
    const rows2 = await rowsOf(run('ruff check .'), tree, [backend, worker, frontend]);
    expect(row(rows2, 'push', 'lint', 'worker').status).toBe('covered');
    const rows3 = await rowsOf(run('ruff check backend/app.py'), tree, [backend, worker, frontend]);
    expect(row(rows3, 'push', 'lint', 'backend').status).toBe('covered');
    expect(st(rows3, 'push', 'lint', 'worker')).toBe('missing');
  });
});

describe('coverage: a detached compose or docker run gives no coverage (P57 C2)', () => {
  const backend = svc('backend', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'] });
  const COMPOSE = 'services:\n  web:\n    build: ./backend\n';
  const unitTests = async (steps: string) => {
    const dir = makeTempDir();
    writeIn(dir, 'compose.yml', COMPOSE);
    writeIn(dir, 'backend/Dockerfile', 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n');
    ci(dir, steps);
    const r = row(await coverage(dir, { services: [backend] }), 'push', 'unit-tests', 'backend');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };

  it('dk probe: compose run -d / --detach and exec -d return at once, so the tests\' failure never reaches the step', async () => {
    for (const steps of [run('docker compose run -d web pytest'), run('docker compose run --detach web pytest'), run('docker compose run --rm -d web pytest'),
      run('docker compose up -d') + run('docker compose exec -d web pytest'), run('docker compose exec --detach web pytest'), run('docker-compose run -d web pytest')]) {
      expect(await unitTests(steps), steps).toBe('missing');
    }
    // the same commands without -d still count
    expect(await unitTests(run('docker compose run --rm web pytest'))).toBe('covered your own `pytest`');
    expect(await unitTests(run('docker compose up -d') + run('docker compose exec -T web pytest'))).toBe('covered your own `pytest`');
  });

  it('docker run -d (also in a group of short flags) runs the container in the background: its command gives no coverage', async () => {
    for (const cmd of ['docker run -d img:1 pytest', 'docker run --detach img:1 pytest', 'docker run -dit img:1 pytest', 'docker run --rm -d -e A=b img:1 pytest']) {
      expect(await unitTests(run(cmd)), cmd).toBe('missing');
    }
  });
});

describe('coverage: pipegen reads the compose files and services Compose really uses, else unknown (P57 C3)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'] });
  const TEST_DOCKERFILE = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\nRUN pytest\n';
  const PLAIN = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n';
  const PROFILED = 'services:\n  app:\n    build: .\n  tests:\n    profiles: [test]\n    build:\n      context: .\n      dockerfile: Dockerfile.test\n';
  const TESTS = 'services:\n  app:\n    build: .\n  tests:\n    build:\n      context: .\n      dockerfile: Dockerfile.test\n';
  const CI_ONLY = 'services:\n  app:\n    build: .\n';
  const st = async (files: Record<string, string>, steps: string) => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries({ Dockerfile: PLAIN, 'Dockerfile.test': TEST_DOCKERFILE, ...files })) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services: [app] }), 'push', 'unit-tests', 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };

  it('dk probe: a service under a profile the command doesn\'t enable is not built, so its RUN lines don\'t run', async () => {
    expect(await st({ 'compose.yml': PROFILED }, run('docker compose build'))).toBe('missing');
    expect(await st({ 'compose.yml': PROFILED }, run('docker compose --profile other build'))).toBe('missing');
    // enabled by --profile, or named on the command line: it is built
    expect(await st({ 'compose.yml': PROFILED }, run('docker compose --profile test build'))).toBe('covered your own `pytest`');
    expect(await st({ 'compose.yml': PROFILED }, run('docker compose build tests'))).toBe('covered your own `pytest`');
    expect(await st({ 'compose.yml': PROFILED }, run('docker compose --profile "*" build'))).toBe('covered your own `pytest`');
    expect(await st({ 'compose.yml': TESTS }, run('docker compose build'))).toBe('covered your own `pytest`'); // control: no profile
  });

  it('dk probe: COMPOSE_FILE or COMPOSE_PROFILES in the step, job or workflow env, or in the repo .env, makes the compose model unknown', async () => {
    const files = { 'compose.yml': TESTS, 'compose.ci.yml': CI_ONLY };
    for (const steps of [
      '      - run: docker compose build\n        env:\n          COMPOSE_FILE: compose.ci.yml\n',
      '      - run: docker compose build\n        env:\n          COMPOSE_PROFILES: x\n',
      run('COMPOSE_FILE=compose.ci.yml docker compose build'),
      run('echo "COMPOSE_FILE=compose.ci.yml" >> "$GITHUB_ENV"') + run('docker compose build'),
    ]) expect(await st(files, steps), steps).toMatch(/^unknown/);
    expect(await st({ ...files, '.env': 'FOO=1\nCOMPOSE_FILE=compose.ci.yml\n' }, run('docker compose build'))).toMatch(/^unknown/);
    expect(await st({ ...files, '.env': 'export COMPOSE_PROFILES=x\n' }, run('docker compose build'))).toMatch(/^unknown/);
    // an unrelated .env changes nothing
    expect(await st({ ...files, '.env': 'FOO=1\n' }, run('docker compose build'))).toBe('covered your own `pytest`');
    // the same rule for compose run
    expect(await st({ 'compose.yml': TESTS }, '      - run: docker compose run --rm tests pytest\n        env:\n          COMPOSE_FILE: compose.ci.yml\n')).toMatch(/^unknown/);
  });

  it('dk probe: an include: or extends: pipegen doesn\'t follow, an --env-file or a -f it can\'t place is unknown, never covered or missing', async () => {
    expect(await st({ 'compose.yml': `include:\n  - other.yml\n${TESTS}` }, run('docker compose build'))).toMatch(/^unknown/);
    expect(await st({ 'compose.yml': `${TESTS}  more:\n    extends:\n      file: base.yml\n      service: x\n` }, run('docker compose build'))).toMatch(/^unknown/);
    expect(await st({ 'compose.yml': TESTS }, run('docker compose --env-file ci.env build'))).toMatch(/^unknown/);
    expect(await st({ 'compose.yml': TESTS }, run('docker compose -f "$COMPOSE" build'))).toMatch(/^unknown/);
  });
});

describe('coverage: prek and pre-commit read SKIP / PREK_SKIP by hook, and prek reads prek.toml first (P57 C4)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...emptyServiceQuality(), pythonTyped: true } });
  const YAML = 'repos:\n  - repo: https://github.com/pre-commit/mirrors-mypy\n    rev: v1.18.2\n    hooks:\n      - id: mypy\n'
    + '  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.16.0\n    hooks:\n      - id: ruff\n      - id: ruff-format\n';
  const TOML_RUFF = '[[repos]]\nrepo = "https://github.com/astral-sh/ruff-pre-commit"\nrev = "v0.16.0"\nhooks = [{ id = "ruff" }]\n';
  const rowsOf = async (steps: string, files: Record<string, string> = {}, extra = '', top = '') => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries({ '.pre-commit-config.yaml': YAML, ...files })) writeIn(dir, rel, text);
    wf(dir, 'ci.yml', `${both}${top}${job(steps, extra)}`);
    return coverage(dir, { services: [app] });
  };
  const st = (rows: Coverage[], id: string) => {
    const r = row(rows, 'push', id, 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  const three = (rows: Coverage[]) => ['lint', 'type-check', 'format'].map((id) => st(rows, id));

  it('the review\'s probe: PREK_SKIP in the step or job env naming mypy and ruff leaves those hooks partial, the others covered', async () => {
    const step = '      - run: prek run --all-files\n        env:\n          PREK_SKIP: mypy,ruff\n';
    expect(three(await rowsOf(step))).toEqual(['partial ruff', 'partial mypy', 'covered ruff-format']);
    expect(three(await rowsOf(run('prek run --all-files'), {}, '    env:\n      PREK_SKIP: mypy,ruff\n'))).toEqual(['partial ruff', 'partial mypy', 'covered ruff-format']);
    expect(three(await rowsOf(run('prek run --all-files'), {}, '', 'env:\n  PREK_SKIP: mypy\n'))).toEqual(['covered ruff', 'partial mypy', 'covered ruff-format']);
    // pre-commit itself doesn't read PREK_SKIP
    expect(three(await rowsOf('      - run: pre-commit run --all-files\n        env:\n          PREK_SKIP: mypy,ruff\n'))).toEqual(['covered ruff', 'covered mypy', 'covered ruff-format']);
  });

  it('SKIP names hooks for pre-commit and prek alike (env, inline, GITHUB_ENV); a value pipegen can\'t read is unknown for every hook of the run', async () => {
    for (const runner of ['prek', 'pre-commit']) {
      expect(three(await rowsOf(`      - run: ${runner} run --all-files\n        env:\n          SKIP: mypy\n`)), runner).toEqual(['covered ruff', 'partial mypy', 'covered ruff-format']);
      expect(three(await rowsOf(run(`SKIP=ruff,ruff-format ${runner} run --all-files`))), runner).toEqual(['partial ruff', 'covered mypy', 'partial ruff-format']);
      expect(three(await rowsOf(run('echo "SKIP=mypy" >> "$GITHUB_ENV"') + run(`${runner} run --all-files`))), runner).toEqual(['covered ruff', 'partial mypy', 'covered ruff-format']);
      const unknown = three(await rowsOf(`      - run: ${runner} run --all-files\n        env:\n          SKIP: \${{ matrix.skip }}\n`));
      expect(unknown.every((x) => x.startsWith('unknown')), `${runner} ${unknown.join()}`).toBe(true);
      const bare = three(await rowsOf(run('export SKIP="$HOOKS"') + run(`${runner} run --all-files`)));
      expect(bare.every((x) => x.startsWith('unknown')), `${runner} ${bare.join()}`).toBe(true);
    }
    // a name that only contains SKIP is not SKIP
    expect(three(await rowsOf(run('SKIP_TESTS=1 prek run --all-files')))).toEqual(['covered ruff', 'covered mypy', 'covered ruff-format']);
  });

  it('the review\'s probe: prek reads prek.toml before .pre-commit-config.yaml, so the YAML\'s hooks are never credited to a prek run then', async () => {
    expect(three(await rowsOf(run('prek run --all-files'), { 'prek.toml': '# nothing here yet\n' }))).toEqual(['missing', 'missing', 'missing']);
    expect(three(await rowsOf(run('prek run --all-files'), { 'prek.toml': TOML_RUFF }))).toEqual(['covered ruff', 'missing', 'missing']);
    // pre-commit itself reads only the YAML
    expect(three(await rowsOf(run('pre-commit run --all-files'), { 'prek.toml': '# nothing\n' }))).toEqual(['covered ruff', 'covered mypy', 'covered ruff-format']);
    // a prek.toml pipegen can't read: unknown, never the YAML's hooks
    const bad = three(await rowsOf(run('prek run --all-files'), { 'prek.toml': '[[repos]\nbroken = \n' }));
    expect(bad.every((x) => x.startsWith('unknown')), bad.join()).toBe(true);
  });
});

describe('coverage: Dockerfile ENV / ARG and a compose service\'s environment go through the env rules (P57 C5)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'] });
  const st = async (dockerfile: string, steps = run('docker build .'), files: Record<string, string> = {}) => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries({ Dockerfile: dockerfile, 'tox.ini': '[tox]\nenv_list = py, lint\n', ...files })) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services: [app] }), 'push', 'unit-tests', 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  const HEAD = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n';

  it('py probe: ENV TOXENV before RUN tox picks the envs, so the run is partial (as RUN TOXENV=lint tox already was)', async () => {
    expect(await st(`${HEAD}ENV TOXENV=lint\nRUN tox\n`)).toBe('partial your own `tox`');
    expect(await st(`${HEAD}ENV TOXENV lint\nRUN tox\n`)).toBe('partial your own `tox`');
    expect(await st(`${HEAD}ENV A=1 TOX_ENV=lint\nRUN tox\n`)).toBe('partial your own `tox`');
    expect(await st(`${HEAD}RUN TOXENV=lint tox\n`)).toBe('partial your own `tox`'); // control
    // inherited from the stage FROM names
    expect(await st('FROM python:3.14 AS base\nENV TOXENV=lint\nFROM base\nWORKDIR /app\nCOPY . /app\nRUN tox\n')).toBe('partial your own `tox`');
    // an ENV after the RUN doesn't reach it
    expect(await st(`${HEAD}RUN tox\nENV TOXENV=lint\n`)).toBe('covered your own `tox`');
  });

  it('ARG (with a build-arg from the CI step or not) counts like ENV', async () => {
    expect(await st(`${HEAD}ARG TOXENV\nRUN tox\n`, run('docker build --build-arg TOXENV=lint .'))).toBe('partial your own `tox`');
    expect(await st(`${HEAD}ARG NOXSESSION=lint\nRUN nox\n`)).toBe('partial your own `nox`');
  });

  it('PYTEST_ADDOPTS (it can add --collect-only or -k) makes a pytest run partial, in a Dockerfile and in a workflow alike', async () => {
    expect(await st(`${HEAD}ENV PYTEST_ADDOPTS="--co"\nRUN pytest\n`)).toBe('partial your own `pytest`');
    expect(await st(HEAD, '      - run: pytest\n        env:\n          PYTEST_ADDOPTS: --co\n')).toBe('partial your own `pytest`');
    expect(await st(`${HEAD}RUN pytest\n`)).toBe('covered your own `pytest`'); // control
  });

  it('compose run: the service\'s environment: and its image\'s ENV reach the command', async () => {
    const compose = (env: string) => `services:\n  web:\n    build: .\n${env}`;
    const steps = run('docker compose run --rm web tox');
    expect(await st(HEAD, steps, { 'compose.yml': compose('    environment:\n      TOXENV: lint\n') })).toBe('partial your own `tox`');
    expect(await st(HEAD, steps, { 'compose.yml': compose('    environment:\n      - TOXENV=lint\n') })).toBe('partial your own `tox`');
    expect(await st(`${HEAD}ENV TOXENV=lint\n`, steps, { 'compose.yml': compose('') })).toBe('partial your own `tox`');
    expect(await st(HEAD, steps, { 'compose.yml': compose('') })).toBe('covered your own `tox`'); // control
  });
});

describe('coverage: SKIP / PREK_SKIP, the follow-ups of the security scan (P57 C4)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...emptyServiceQuality(), pythonTyped: true } });
  const YAML = 'repos:\n  - repo: https://github.com/pre-commit/mirrors-mypy\n    rev: v1.18.2\n    hooks:\n      - id: mypy\n        alias: types\n'
    + '  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.16.0\n    hooks:\n      - id: ruff\n';
  const two = async (steps: string, files: Record<string, string> = {}) => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries({ '.pre-commit-config.yaml': YAML, ...files })) writeIn(dir, rel, text);
    wf(dir, 'ci.yml', `${both}${job(steps)}`);
    const rows = await coverage(dir, { services: [app] });
    return ['lint', 'type-check'].map((id) => { const r = row(rows, 'push', id, 'app'); return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`; });
  };

  it('a hook is skipped when SKIP or PREK_SKIP names its alias, in the YAML and in prek.toml', async () => {
    expect(await two(run('SKIP=types pre-commit run --all-files'))).toEqual(['covered ruff', 'partial mypy']);
    expect(await two(run('PREK_SKIP=types prek run --all-files'))).toEqual(['covered ruff', 'partial mypy']);
    const toml = '[[repos]]\nrepo = "https://github.com/pre-commit/mirrors-mypy"\nrev = "v1.18.2"\nhooks = [{ id = "mypy", alias = "types" }]\n';
    expect(await two(run('SKIP=types prek run --all-files'), { 'prek.toml': toml })).toEqual(['missing', 'partial mypy']);
  });

  it('a value glued to quotes or other text is not the literal it looks like: unknown for every hook', async () => {
    for (const cmd of ['SKIP="ruff"mypy prek run --all-files', 'SKIP=ruff"x mypy" prek run --all-files', "SKIP='ruff'$X prek run --all-files",
      'SKIP=ruff\\x prek run --all-files', 'echo SKIP=ruff`x` >> "$GITHUB_ENV"', 'echo "SKIP=ruff"mypy >> "$GITHUB_ENV"']) {
      const steps = cmd.startsWith('echo') ? run(JSON.stringify(cmd)) + run('prek run --all-files') : run(JSON.stringify(cmd));
      const out = await two(steps);
      expect(out.every((x) => x.startsWith('unknown')), `${cmd}: ${out.join()}`).toBe(true);
    }
    // a quoted value, or one a quoted echo closes, is still read
    expect(await two(run('SKIP="mypy" prek run --all-files'))).toEqual(['covered ruff', 'partial mypy']);
    expect(await two(run('echo "SKIP=mypy" >> "$GITHUB_ENV"') + run('prek run --all-files'))).toEqual(['covered ruff', 'partial mypy']);
  });

  it('a value longer than 300 characters is read to its end (the hook named last is skipped)', async () => {
    const long = `${Array.from({ length: 80 }, (_, i) => `hook${i}`).join(',')},mypy`;
    expect(long.length).toBeGreaterThan(300);
    expect(await two(run(`SKIP=${long} prek run --all-files`))).toEqual(['covered ruff', 'partial mypy']);
    expect(await two(`      - run: prek run --all-files\n        env:\n          SKIP: ${long}\n`)).toEqual(['covered ruff', 'partial mypy']);
  });
});

describe('coverage: minors of the hand-check fixes review (P57)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'] });
  const st = async (files: Record<string, string>, steps: string) => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services: [app] }), 'push', 'unit-tests', 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  const BODY = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\nRUN pytest\n';

  it('M3: a # syntax= directive naming a frontend other than docker/dockerfile can change how the file is read: unknown', async () => {
    for (const d of ['# syntax=docker/dockerfile:1', '# syntax=docker/dockerfile:1.7-labs', '# syntax = docker.io/docker/dockerfile:1']) {
      expect(await st({ Dockerfile: `${d}\n${BODY}` }, run('docker build .')), d).toBe('covered your own `pytest`');
    }
    for (const d of ['# syntax=ghcr.io/evil/frontend:1', '# syntax=docker/dockerfile-upstream:master', '#syntax=example.com/x']) {
      expect(await st({ Dockerfile: `${d}\n${BODY}` }, run('docker build .')), d).toMatch(/^unknown/);
    }
  });
});

describe('coverage: a custom BuildKit frontend makes a Dockerfile build unknown (P57 M3, security scan follow-up)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'] });
  const BODY = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\nRUN pytest\n';
  const st = async (files: Record<string, string>, steps: string) => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services: [app] }), 'push', 'unit-tests', 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  const build = run('docker build .');

  it('every directive form BuildKit reads in the leading block: // and #, any case, spaces, after other directives; a JSON file with a syntax key', async () => {
    for (const head of ['// syntax=evil/frontend', '# SyNtAx = x', '#syntax=evil/fe', '# check=skip=all\n# syntax=evil/fe', '//syntax = docker/dockerfile-upstream:master',
      '# escape=\\\n# syntax=evil/fe', '\ufeff# syntax=evil/fe']) {
      expect(await st({ Dockerfile: `${head}\n${BODY}` }, build), head).toMatch(/^unknown/);
    }
    expect(await st({ Dockerfile: '{"syntax": "evil/fe", "x": "FROM python:3.14\\nRUN pytest"}\n' }, build)).toMatch(/^unknown/);
    // Docker's own frontend, and a syntax line after the leading block (a plain comment then), still read
    expect(await st({ Dockerfile: `// syntax=docker/dockerfile:1\n${BODY}` }, build)).toBe('covered your own `pytest`');
    expect(await st({ Dockerfile: `${BODY}# syntax=evil/fe\n` }, build)).toBe('covered your own `pytest`');
  });

  it('BUILDKIT_SYNTAX as a build arg (command line, from the env, compose args, the build action) or a frontend option: unknown', async () => {
    for (const steps of [run('docker build --build-arg BUILDKIT_SYNTAX=evil/fe .'), run('docker buildx build --build-arg=BUILDKIT_SYNTAX=evil/fe .'),
      run('docker build --build-arg BUILDKIT_SYNTAX .'), run('docker build --build-arg BUILDKIT_SYNTAX="$FE" .'), run('docker buildx build --opt source=x .'),
      run('docker build --weird-flag .'),
      '      - uses: docker/build-push-action@v6\n        with:\n          build-args: |\n            BUILDKIT_SYNTAX=evil/fe\n']) {
      expect(await st({ Dockerfile: BODY }, steps), steps).toMatch(/^unknown/);
    }
    expect(await st({ Dockerfile: BODY }, run('docker build --build-arg BUILDKIT_SYNTAX=docker/dockerfile:1 .'))).toBe('covered your own `pytest`');
    expect(await st({ Dockerfile: BODY }, run('docker build --build-arg OTHER=1 .'))).toBe('covered your own `pytest`');
    const compose = (args: string) => ({ Dockerfile: BODY, 'compose.yml': `services:\n  app:\n    build:\n      context: .\n      args:\n${args}` });
    expect(await st(compose('        BUILDKIT_SYNTAX: evil/fe\n'), run('docker compose build'))).toMatch(/^unknown/);
    expect(await st(compose('        - BUILDKIT_SYNTAX=evil/fe\n'), run('docker compose build'))).toMatch(/^unknown/);
    expect(await st(compose('        OTHER: "1"\n'), run('docker compose build'))).toBe('covered your own `pytest`');
  });
});

describe('coverage: prek run flags (P57 M2)', () => {
  const lint = async (cmd: string) => {
    const dir = makeTempDir();
    writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
    ci(dir, run(cmd));
    const r = row(await coverage(dir, pyApp), 'merge', 'lint', 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  it('--last-commit runs the hooks on the last commit\'s files only (partial); --stage is --hook-stage', async () => {
    expect(await lint('prek run --last-commit')).toBe('partial ruff');
    expect(await lint('prek run --all-files --stage pre-commit')).toBe('covered ruff');
    expect(await lint('prek run --all-files --stage manual')).toBe('missing');
  });
});

describe('coverage: every cap in the Docker, compose, prek and env code fails closed (P57, security scan follow-up)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'] });
  const BODY = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\nRUN pytest\n';
  const st = async (files: Record<string, string>, steps: string, id = 'unit-tests', layer: Layer = 'push') => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services: [app] }), layer, id, 'app');
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  const many = (n: number, f: (i: number) => string) => Array.from({ length: n }, (_, i) => f(i)).join('');

  it('1. docker compose build --build-arg BUILDKIT_SYNTAX (= and next-word forms, a value from the env): unknown', async () => {
    const files = { Dockerfile: BODY, 'compose.yml': 'services:\n  app:\n    build: .\n' };
    for (const cmd of ['docker compose build --build-arg BUILDKIT_SYNTAX=evil/fe', 'docker compose build --build-arg=BUILDKIT_SYNTAX=evil/fe', 'docker compose build --build-arg BUILDKIT_SYNTAX app']) {
      expect(await st(files, run(cmd)), cmd).toMatch(/^unknown/);
    }
    expect(await st(files, run('docker compose build --build-arg BUILDKIT_SYNTAX=docker/dockerfile:1'))).toBe('covered your own `pytest`');
  });

  it('2. compose build args, environment and services past any cap are still read, or unknown', async () => {
    const args = (list: boolean) => ({ Dockerfile: BODY, 'compose.yml': `services:\n  app:\n    build:\n      context: .\n      args:\n${list ? many(250, (i) => `        - A${i}=1\n`) + '        - BUILDKIT_SYNTAX=evil/fe\n' : many(250, (i) => `        A${i}: "1"\n`) + '        BUILDKIT_SYNTAX: evil/fe\n'}` });
    expect(await st(args(true), run('docker compose build'))).toMatch(/^unknown/);
    expect(await st(args(false), run('docker compose build'))).toMatch(/^unknown/);
    const env = { Dockerfile: 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n', 'tox.ini': '[tox]\n', 'compose.yml': `services:\n  app:\n    build: .\n    environment:\n${many(250, (i) => `      A${i}: "1"\n`)}      TOXENV: lint\n` };
    expect(await st(env, run('docker compose run --rm app tox'))).toBe('partial your own `tox`');
    const services = { Dockerfile: BODY, 'compose.yml': `services:\n${many(200, (i) => `  s${i}:\n    image: x\n`)}  app:\n    build: .\n` };
    expect(await st(services, run('docker compose build'))).toMatch(/^unknown/);
  });

  it('3. the leading directive block is read to its end: a syntax or escape directive past line 200 (or 5) still counts', async () => {
    expect(await st({ Dockerfile: `${many(250, (i) => `# check${i}=x\n`)}# syntax=evil/fe\n${BODY}` }, run('docker build .'))).toMatch(/^unknown/);
    expect(await st({ Dockerfile: `${many(6, (i) => `# check${i}=x\n`)}# escape=\`\n${BODY}` }, run('docker build .'))).toMatch(/^unknown/);
  });

  it('the rest of the class: a RUN with more flags than read, a compose or docker build line longer than read, an env: with more keys than read', async () => {
    const flags = many(9, (i) => `--mount=type=cache,target=/c${i} `);
    expect(await st({ Dockerfile: `FROM python:3.14 AS t\nWORKDIR /app\nCOPY . /app\nRUN pytest\nFROM python:3.14\nRUN ${flags}--mount=from=t,target=/x echo\n` }, run('docker build .'))).toMatch(/^unknown/);
    const long = many(70, (i) => ` --build-arg A${i}=1`);
    expect(await st({ Dockerfile: BODY }, run(`docker build${long} .`))).toMatch(/^unknown/);
    expect(await st({ Dockerfile: BODY, 'compose.yml': 'services:\n  app:\n    build: .\n' }, run(`docker compose build${long}`))).toMatch(/^unknown/);
    const envKeys = `      - run: tox\n        env:\n${many(300, (i) => `          A${i}: "1"\n`)}          TOXENV: lint\n`;
    expect(await st({ 'tox.ini': '[tox]\n' }, envKeys)).not.toBe('covered your own `tox`');
  });

  it('the rest of the class: more pre-commit hooks than read, a hook entry longer than read, more path arguments than read', async () => {
    const cfg = `repos:\n  - repo: local\n    hooks:\n${many(200, (i) => `      - id: h${i}\n        name: h\n        entry: "true"\n        language: system\n`)}      - id: r\n        name: r\n        entry: ruff check\n        language: system\n`;
    expect(await st({ '.pre-commit-config.yaml': cfg }, run('pre-commit run --all-files'), 'lint', 'merge')).toMatch(/^unknown/);
    const longEntry = `repos:\n  - repo: local\n    hooks:\n      - id: r\n        name: r\n        entry: ruff check${many(70, (i) => ` a${i}`)} --exit-zero\n        language: system\n`;
    expect(await st({ '.pre-commit-config.yaml': longEntry }, run('pre-commit run --all-files'), 'lint', 'merge')).not.toBe('covered ruff');
    const dirs: Record<string, string> = {};
    for (let i = 0; i < 40; i++) dirs[`d${i}/a.py`] = 'x = 1\n'; // more than pipegen places (32), fewer than it reads (64)
    expect(await st(dirs, run(`ruff check ${Object.keys(dirs).map((f) => f.split('/')[0]).join(' ')}`), 'lint')).not.toBe('covered ruff');
  });
});

describe('coverage: ruling P59 (round 2)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'], quality: { ...emptyServiceQuality(), pythonTyped: true } });
  const st = async (files: Record<string, string>, steps: string, id = 'unit-tests', services = [app], service = 'app') => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services }), 'push', id, service);
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };

  it('1. a command given through a variable is never credited to any tool', async () => {
    const BODY = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n';
    expect(await st({ Dockerfile: `${BODY}ARG TEST_CMD=pytest\nRUN $TEST_CMD\n` }, run('docker build .'))).toBe('missing');
    for (const cmd of ['$CMD pytest', '${RUNNER} pytest', '"$PY" -m pytest', '$TOOL']) expect(await st({}, run(cmd)), cmd).toBe('missing');
    expect(await st({ 'package.json': JSON.stringify({ name: 'a', scripts: { ci: '$X pytest' } }) }, run('npm run ci'))).toBe('missing');
    const { CANT_SEE } = await import('../src/audit/render.js');
    expect(CANT_SEE).toContain("Commands given through a variable aren't read.");
  });

  it('2. prek --directory / --glob and pre-commit --files run on part of the repo: partial with their own reason', async () => {
    for (const cmd of ['prek run --all-files --directory backend', 'prek run --all-files -d backend', 'prek run --all-files --glob "*.py"', 'pre-commit run --files a.py b.py', 'prek run --files a.py']) {
      const dir = makeTempDir();
      writeIn(dir, '.pre-commit-config.yaml', hookConfig('      - id: ruff-check\n'));
      ci(dir, run(cmd));
      const r = row(await coverage(dir, pyApp), 'merge', 'lint', 'app');
      expect(`${r.status} ${r.by ?? ''}`, cmd).toBe('partial ruff');
      expect(r.why, cmd).toMatch(/runs only on part of the repo/);
    }
  });

  it('3. a path argument pipegen can\'t place never falls back to the run\'s whole folder: unknown, never covered', async () => {
    const backend = svc('backend', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...emptyServiceQuality(), pythonTyped: true } });
    const worker = svc('worker', { language: 'python', packageManager: 'uv', scripts: [], quality: { ...emptyServiceQuality(), pythonTyped: true } });
    const tree = { 'backend/app.py': 'x = 1\n', 'worker/w.py': 'x = 1\n' };
    for (const cmd of ['mypy $DIRS', 'mypy "$SRC"', 'mypy backend/**/x*.py', 'mypy ../elsewhere', 'mypy --strict $DIR', 'pytest $TESTS']) {
      const id = cmd.startsWith('pytest') ? 'unit-tests' : 'type-check';
      for (const s of ['backend', 'worker']) expect(await st(tree, run(cmd), id, [backend, worker], s), `${cmd} ${s}`).toMatch(/^unknown/);
    }
    // a flag's quoted value is not a path; plain paths and subcommands still read as before
    expect(await st(tree, run('pytest -k "not slow"'), 'unit-tests', [backend, worker], 'worker')).toBe('covered your own `pytest`');
    expect(await st(tree, run('mypy backend'), 'type-check', [backend, worker], 'worker')).toBe('missing');
    expect(await st(tree, run('ruff check .'), 'lint', [backend, worker], 'worker')).toBe('covered ruff');
  });

  it('4. a compose command inside a package script, with COMPOSE_FILE or COMPOSE_PROFILES set in the job: unknown, not missing', async () => {
    const files = {
      'package.json': JSON.stringify({ name: 'a', scripts: { ci: 'docker compose run --rm app pytest', build: 'docker compose build' } }),
      'compose.ci.yml': 'services:\n  app:\n    build: .\n', Dockerfile: 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n',
    };
    expect(await st(files, '      - run: npm run ci\n        env:\n          COMPOSE_FILE: compose.ci.yml\n')).toMatch(/^unknown/);
    const profiled = {
      'package.json': JSON.stringify({ name: 'a', scripts: { build: 'docker compose build' } }), Dockerfile: 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n',
      'Dockerfile.test': 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\nRUN pytest\n',
      'compose.yml': 'services:\n  app:\n    build: .\n  tests:\n    profiles: [test]\n    build:\n      context: .\n      dockerfile: Dockerfile.test\n',
    };
    expect(await st(profiled, '      - run: npm run build\n        env:\n          COMPOSE_PROFILES: test\n')).toMatch(/^unknown/);
    // without the variable: the default file decides (no compose file → the runner fails → missing; the profile is off → missing)
    expect(await st(files, run('npm run ci'))).toBe('missing');
    expect(await st(profiled, run('npm run build'))).toBe('missing');
  });
});

describe('coverage: closing patch (ruling P60)', () => {
  const app = svc('.', { language: 'python', packageManager: 'uv', scripts: ['start'], frameworks: ['fastapi'], quality: { ...emptyServiceQuality(), pythonTyped: true } });
  const st = async (files: Record<string, string>, steps: string, id = 'unit-tests', services = [app], service = 'app', layer: Layer = 'push') => {
    const dir = makeTempDir();
    for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
    ci(dir, steps);
    const r = row(await coverage(dir, { services }), layer, id, service);
    return `${r.status}${r.by === undefined ? '' : ` ${r.by}`}`;
  };
  const IMG = 'FROM python:3.14\nWORKDIR /app\nCOPY . /app\n';

  it('R1: a compose service\'s env_file: goes through the env rules; one pipegen can\'t read is unsure', async () => {
    const compose = (envFile: string) => ({ Dockerfile: IMG, 'tox.ini': '[tox]\n', 'compose.yml': `services:\n  app:\n    build: .\n    env_file: ${envFile}\n` });
    const steps = run('docker compose run --rm app tox');
    expect(await st({ ...compose('ci.env'), 'ci.env': 'TOXENV=lint\n' }, steps)).toBe('partial your own `tox`');
    expect(await st({ ...compose('[ci.env]'), 'ci.env': '# c\nexport TOXENV=lint\n' }, steps)).toBe('partial your own `tox`');
    expect(await st({ ...compose('\n      - path: ci.env\n        required: true'), 'ci.env': 'TOXENV=lint\n' }, steps)).toBe('partial your own `tox`');
    // a file that sets nothing that matters changes nothing
    expect(await st({ ...compose('ci.env'), 'ci.env': 'FOO=1\n' }, steps)).toBe('covered your own `tox`');
    // a file pipegen can't read (missing, a variable path) is unsure: never covered
    expect(await st(compose('missing.env'), steps)).not.toBe('covered your own `tox`');
    expect(await st(compose('${ENV_FILE}'), steps)).not.toBe('covered your own `tox`');
  });

  it('R3: a build arg whose name pipegen can\'t read (a variable, a quoted expression) is unsure', async () => {
    const BODY = `${IMG}RUN pytest\n`;
    for (const cmd of ['docker build --build-arg "$ARGS" .', 'docker build --build-arg $A .', 'docker buildx build --build-arg=${A}=x .']) {
      expect(await st({ Dockerfile: BODY }, run(cmd)), cmd).toMatch(/^unknown/);
    }
    const compose = (extra: string) => ({ Dockerfile: BODY, 'compose.yml': `services:\n  app:\n    build:\n      context: .\n${extra}` });
    expect(await st(compose(''), run('docker compose build --build-arg $A'))).toMatch(/^unknown/);
    expect(await st(compose('      args:\n        ${K}: x\n'), run('docker compose build'))).toMatch(/^unknown/);
    expect(await st(compose('      args:\n        - ${K}=x\n'), run('docker compose build'))).toMatch(/^unknown/);
    expect(await st({ Dockerfile: BODY }, run('docker build --build-arg A=$B .'))).toBe('covered your own `pytest`'); // a variable value of a plain name is fine
  });

  it('R4: a Python folder with a package.json (an asset build) is Python and Node: tools of either language cover it', async () => {
    const { readProject } = await import('../src/read/project.js');
    const dir = makeTempDir();
    writeIn(dir, 'package.json', JSON.stringify({ name: 'root', private: true, workspaces: ['backend', 'frontend'] }));
    writeIn(dir, 'backend/pyproject.toml', '[project]\nname = "be"\ndependencies = ["django"]\n');
    writeIn(dir, 'backend/package.json', JSON.stringify({ name: 'be-assets', scripts: { build: 'webpack' } }));
    writeIn(dir, 'backend/app/main.py', 'x = 1\n');
    writeIn(dir, 'backend/Dockerfile', 'FROM python:3.14\n');
    writeIn(dir, 'frontend/package.json', JSON.stringify({ name: 'fe', scripts: { dev: 'vite', test: 'vitest run' } }));
    writeIn(dir, 'frontend/src/a.ts', 'x\n');
    ci(dir, run('cd backend && pytest') + run('cd frontend && npx vitest run'));
    const { execFileSync } = await import('node:child_process');
    execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'pipe' });
    execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/o/r.git'], { cwd: dir, stdio: 'pipe' });
    const p = { ...(await readProject(dir)), private: false, ownerType: 'User' as const, plan: 'free' as const };
    const be = p.services.find((x) => x.path === 'backend')!;
    expect([be.language, ...(be.alsoLanguages ?? [])].sort()).toEqual(['node', 'python']);
    expect(p.services.find((x) => x.path === 'frontend')!.alsoLanguages).toBeUndefined();
    const rows = await mapCoverage(p, floorNeeds(p, caps), dir);
    expect(row(rows, 'push', 'unit-tests', be.name)).toMatchObject({ status: 'covered', by: 'your own `pytest`' });
  });

  it('R1 follow-up: env_file lists merge across compose files like Compose does; a bare NAME passes the env through (unsure)', async () => {
    const steps = run('docker compose run --rm app tox');
    const base = { Dockerfile: IMG, 'tox.ini': '[tox]\n', 'compose.yml': 'services:\n  app:\n    build: .\n    env_file: a.env\n', 'a.env': 'TOXENV=lint\n' };
    // the override adds b.env; a.env still applies (Compose concatenates the lists)
    expect(await st({ ...base, 'compose.override.yml': 'services:\n  app:\n    env_file: b.env\n', 'b.env': 'FOO=1\n' }, steps)).toBe('partial your own `tox`');
    expect(await st({ ...base, 'a.env': 'FOO=1\n', 'compose.override.yml': 'services:\n  app:\n    env_file: ${X}\n' }, steps)).not.toBe('covered your own `tox`');
    // a bare SKIP line takes its value from the environment: pipegen can't read it, so the hooks are unknown
    const hooks = { Dockerfile: IMG, '.pre-commit-config.yaml': hookConfig('      - id: ruff-check\n'), 'compose.yml': 'services:\n  app:\n    build: .\n    env_file: a.env\n' };
    const lint = (aEnv: string) => st({ ...hooks, 'a.env': aEnv }, run('docker compose run --rm app prek run --all-files'), 'lint');
    expect(await lint('SKIP\n')).toMatch(/^unknown/);
    expect(await lint('export SKIP\n')).toMatch(/^unknown/);
    expect(await lint('FOO=1\n')).toBe('covered ruff');
  });

  it('R5: a detached docker or compose run inside a followed package script is partial, like `&`', async () => {
    const node = svc('.', { scripts: ['test', 'start'] });
    const byName = (test: string) => st({ 'package.json': JSON.stringify({ name: 'a', scripts: { test } }), 'compose.yml': 'services:\n  app:\n    build: .\n', Dockerfile: 'FROM node:22\nWORKDIR /app\nCOPY . /app\n' },
      run('npm test'), 'unit-tests', [node], 'app');
    for (const t of ['docker compose run -d app npm test', 'docker compose run --detach app vitest run', 'docker run -d img:1 vitest', 'docker compose up -d', 'docker compose exec -d app vitest run', 'docker compose run -dT app vitest run']) {
      expect(await byName(t), t).toBe('partial your own `npm test`');
    }
    expect(await byName('vitest run &')).toBe('partial your own `npm test`'); // the same as the background &
    expect(await byName('docker compose up --exit-code-from app')).toBe('covered your own `npm test`'); // waits: trusted by name
    // a script followed by its text: the detached command counts as a background run
    const files = { 'package.json': JSON.stringify({ name: 'a', scripts: { ci: 'docker compose run -d app pytest' } }), 'compose.yml': 'services:\n  app:\n    build: .\n', Dockerfile: IMG };
    expect(await st(files, run('npm run ci'))).toBe('partial your own `npm run ci`');
    // directly in a step it still gives no coverage (C2)
    expect(await st(files, run('docker compose run -d app pytest'))).toBe('missing');
  });

  it('R2: semgrep\'s languages come from its config; CodeQL\'s from its init languages (m2)', async () => {
    const backend = svc('backend', { language: 'python', packageManager: 'uv', scripts: [] });
    const frontend = svc('frontend', { quality: { ...emptyServiceQuality(), tsconfig: true } });
    const sast = async (steps: string, files: Record<string, string> = {}, extra = '') => {
      const dir = makeTempDir();
      for (const [rel, text] of Object.entries({ 'backend/app.py': 'x = 1\n', 'frontend/a.ts': 'x\n', ...files })) writeIn(dir, rel, text);
      wf(dir, 'ci.yml', `${both}${job(steps, extra)}`);
      const rows = await coverage(dir, { services: [backend, frontend] });
      return ['backend', 'frontend'].map((sv) => row(rows, 'merge', 'sast', sv).status);
    };
    expect(await sast(run('semgrep scan --config p/python --error'))).toEqual(['covered', 'missing']);
    expect(await sast(run('semgrep scan --config=p/django --config p/flask --error .'))).toEqual(['covered', 'missing']);
    expect(await sast(run('semgrep ci --config p/typescript'))).toEqual(['missing', 'covered']);
    expect(await sast(run('semgrep scan -c r/python.lang.security.audit.x --error'))).toEqual(['covered', 'missing']);
    for (const cmd of ['semgrep scan --config auto --error', 'semgrep scan --config p/default --error', 'semgrep ci', 'semgrep scan --config p/python --config p/javascript --error']) {
      expect(await sast(run(cmd)), cmd).toEqual(['covered', 'covered']);
    }
    // a config pipegen can't read: partial for every service
    for (const cmd of ['semgrep scan --config $RULES --error', 'semgrep scan --config rules/ --error', 'semgrep scan --config https://x.test/r.yml --error', 'semgrep scan --config p/some-new-pack --error']) {
      expect(await sast(run(cmd), { 'rules/a.yml': 'rules: []\n' }), cmd).toEqual(['partial', 'partial']);
    }
    // a local rules file: the languages its rules list
    const local = { 'semgrep.yml': 'rules:\n  - id: a\n    languages: [python]\n    pattern: eval(...)\n    message: m\n    severity: ERROR\n' };
    expect(await sast(run('semgrep scan --config semgrep.yml --error'), local)).toEqual(['covered', 'missing']);
    expect(await sast(run('semgrep scan --config semgrep.yml --error'), { 'semgrep.yml': 'rules: [{id: a, languages: [generic], pattern: x, message: m, severity: ERROR}]\n' })).toEqual(['covered', 'covered']);
    // the semgrep action's config input
    expect(await sast('      - uses: semgrep/semgrep-action@v1\n        with:\n          config: p/python\n')).toEqual(['covered', 'missing']);
    // CodeQL: the init step's languages; a language it isn't set to scan is missing, not partial (m2)
    const codeql = (langs: string) => `      - uses: github/codeql-action/init@v3\n${langs}      - uses: github/codeql-action/analyze@v3\n`;
    expect(await sast(codeql('        with:\n          languages: python\n'))).toEqual(['partial', 'missing']);
    expect(await sast(codeql('        with:\n          languages: ${{ matrix.language }}\n'), {}, '    strategy:\n      matrix:\n        language: [javascript-typescript]\n')).toEqual(['missing', 'partial']);
    expect(await sast(codeql(''))).toEqual(['partial', 'partial']); // autodetect
    expect(await sast(codeql('        with:\n          languages: ${{ inputs.l }}\n'))).toEqual(['partial', 'partial']);
  });

  it('m1: a Dockerfile ENV or ARG whose key isn\'t a plain name is unsure, never dropped', async () => {
    for (const line of ['ENV "TOXENV"="lint"', 'ARG N=TOXENV\nENV ${N}=lint', "ENV 'TOXENV' lint", 'ENV $N=lint', 'ARG "TOXENV"']) {
      expect(await st({ Dockerfile: `${IMG}${line}\nRUN tox\n`, 'tox.ini': '[tox]\n' }, run('docker build .')), line).not.toBe('covered your own `tox`');
    }
    expect(await st({ Dockerfile: `${IMG}ENV FOO=1\nRUN tox\n`, 'tox.ini': '[tox]\n' }, run('docker build .'))).toBe('covered your own `tox`');
  });

  it('m3: prek run --skip <hook> lowers only the hooks it names; a value pipegen can\'t read is unknown for every hook', async () => {
    const YAML = 'repos:\n  - repo: https://github.com/pre-commit/mirrors-mypy\n    rev: v1.18.2\n    hooks:\n      - id: mypy\n'
      + '  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.16.0\n    hooks:\n      - id: ruff\n';
    const two = async (cmd: string) => ['lint', 'type-check'].map(async (id) => st({ '.pre-commit-config.yaml': YAML }, run(cmd), id));
    const both2 = async (cmd: string) => Promise.all(await two(cmd));
    expect(await both2('prek run --all-files --skip mypy')).toEqual(['covered ruff', 'partial mypy']);
    expect(await both2('prek run --all-files --skip=mypy')).toEqual(['covered ruff', 'partial mypy']);
    expect(await both2('prek run --all-files --skip mypy --skip ruff')).toEqual(['partial ruff', 'partial mypy']);
    const unknown = await both2('prek run --all-files --skip "$S"');
    expect(unknown.every((x) => x.startsWith('unknown')), unknown.join()).toBe(true);
  });
});
