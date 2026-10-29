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

  it('python runners (adversarial): uv run wrapping something that is not a test runner, and tox or nox runs that pick other envs on the command line → missing', async () => {
    for (const steps of [
      run('uv run --group dev python scripts/build.py'), run('uv run --with ruff python -c pass'), run('uv run --with pytest python -c pass'),
      run('uv run --some-new-flag pytest'), run('uv run -qx pytest'), run('tox run -e typing'), run('tox -e py312'), run('tox list'), run('tox run --notest'),
      run('tox -re lint'), run('tox --override testenv.commands=true'), run('nox -s lint'), run('nox --list'), run('nox -k lint'),
    ]) {
      const dir = makeTempDir();
      ci(dir, steps);
      expect(row(await coverage(dir), 'push', 'unit-tests', 'app').status, steps).toBe('missing');
    }
  });

  it('python runners (adversarial): a TOX… or NOX… variable that may pick other envs → partial, never covered (Plan U final review I2)', async () => {
    for (const steps of [
      run('TOXENV=lint tox'), '      - run: tox run\n        env:\n          TOX_ENV: lint\n', '      - run: tox run\n        env:\n          TOXENV: lint\n',
      '      - run: nox\n        env:\n          NOXSESSION: lint\n', run('echo "TOXENV=lint" >> "$GITHUB_ENV"') + run('tox run'),
    ]) {
      const dir = makeTempDir();
      ci(dir, steps);
      expect(row(await coverage(dir), 'push', 'unit-tests', 'app').status, steps).toBe('partial');
    }
    // an env set for the whole job or workflow picks the envs too
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${both}env:\n  TOX_ENV: lint\n${job(run('tox run'))}`);
    expect(row(await coverage(dir), 'push', 'unit-tests', 'app').status).toBe('partial');
    const dir2 = makeTempDir();
    ci(dir2, run('tox run'), '    env:\n      TOX_ENV: lint\n');
    expect(row(await coverage(dir2), 'push', 'unit-tests', 'app').status).toBe('partial');
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
      ['npm test', { test: 'npm run a && jest', a: 'echo ok' }, 'covered'],
      ['npm test', { test: 'npm run a', a: 'tape test.js' }, 'covered'],
      ['npm test', { test: 'test -f x || exit 0; node t.js' }, 'covered'],
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
      ['true && jest', 'covered'], ['false || jest', 'covered'], ['true || jest; jest', 'covered']]) {
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
    expect(row(rows, 'merge', 'lint', 'app').status).toBe('missing');
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
    expect(row(rows, 'merge', 'lint', 'app').status).toBe('missing');
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
    for (const r of testRows(await coverage(dir))) expect(r, `${r.need.layer} ${r.need.id}`).toMatchObject({ status: 'partial', by: 'your own `tox run`', why: TOX_WHY });
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
      for (const r of testRows(await coverage(dir))) {
        expect(r.status, body).toBe('partial');
        expect(r.by, body).toBe(by);
        expect(r.why, body).toMatch(/a TOX… variable in this job \(like TOXENV\) picks which tox environments run, so pipegen can't tell if it runs the tests\.$/);
      }
    }
  });

  it('I2: a NOX… variable (NOXSESSION) makes a nox run partial the same way', async () => {
    const dir = makeTempDir();
    ci(dir, '      - run: nox\n        env:\n          NOXSESSION: ${{ matrix.session }}\n');
    for (const r of testRows(await coverage(dir))) {
      expect(r).toMatchObject({ status: 'partial', by: 'your own `nox`' });
      expect(r.why).toBe("Your own `nox` runs, but a NOX… variable in this job (like NOXSESSION) picks which nox sessions run, so pipegen can't tell if it runs the tests.");
    }
  });

  it('I2: another run that covers the tests still wins over the partial tox run', async () => {
    const dir = makeTempDir();
    ci(dir, '      - run: tox run\n        env:\n          TOXENV: ${{ matrix.toxenv }}\n' + run('pytest'));
    expect(row(await coverage(dir), 'push', 'unit-tests', 'app')).toMatchObject({ status: 'covered', by: 'your own `pytest`' });
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
    expect(await rowOf(ciRun('go mod tidy -diff'), 'merge', 'dead-code', {}, 'app')).toMatchObject({ status: 'covered', by: 'go-mod-tidy' });
    expect((await rowOf(ciRun('go mod tidy'), 'merge', 'dead-code', {}, 'app')).status).toBe('missing');
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
    // SKIP drops the carry; a hook-stage run on staged files carries nothing
    const dir2 = makeTempDir();
    writeIn(dir2, '.pre-commit-config.yaml', 'repos:\n  - repo: https://github.com/psf/black-pre-commit-mirror\n    rev: 24.8.0\n    hooks:\n      - id: black\n');
    ci(dir2, run('SKIP=black pre-commit run --all-files'));
    expect(row(await cov(dir2, { services: [pySvc] }), 'merge', 'format', 'app').status).toBe('missing');
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
      const r = row(await cov(dir, { services: [pySvc] }), 'merge', 'format', 'app');
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
    const over = { services: [svc('.', { quality: { ...q, fuzzTargets: true } })] };
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
      const r = await rowOf(ciRun(cmd), 'merge', 'coverage', {}, 'app');
      expect(r, cmd).toMatchObject({ status: 'partial', by });
      // Plan P Task 4: vitest, jest and pytest runs are checked for a minimum (config-checks.test.ts); the others still aren't
      expect(r.why, cmd).toMatch(['vitest-cov', 'jest-cov', 'pytest-cov'].includes(by) ? /sets no minimum, so a drop can't fail the build/ : /hasn't checked for a minimum/);
    }
    for (const cmd of ['vitest run', 'vitest --coverage=false', 'vitest --coverage.enabled=false', 'jest', 'pytest --no-cov --cov=x', 'go test ./...']) {
      expect((await rowOf(ciRun(cmd), 'merge', 'coverage', {}, 'app')).status, cmd).toBe('missing');
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
    expect(row(out, 'merge', 'unit-tests', 'app').status).toBe('missing'); // `..` is never followed (not a repo script path)
  });

  it('coverage: `coverage run -m pytest` runs the tests; a flag whose value is the next word stops it', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on: [push, pull_request]\n${job('      - run: coverage run --branch -m pytest tests/\n')}`);
    expect(row(await coverage(dir), 'merge', 'unit-tests').status).toBe('covered');
    const odd = makeTempDir();
    wf(odd, 'ci.yml', `on: [push, pull_request]\n${job('      - run: coverage run --rcfile cfg -m pytest tests/\n')}`);
    expect(row(await coverage(odd), 'merge', 'unit-tests').status).toBe('missing');
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
    expect(row(rows, 'merge', 'unit-tests').why).toMatch(/^pipegen doesn't support this language yet/);
    // Node keeps "missing"
    const node = await coverage(makeTempDir());
    expect(row(node, 'merge', 'unit-tests').status).toBe('missing');
  });
});
