// J3a (DECISIONS #122, ruling B4, S5, S17): credit what the repo already has that does a check's job by other means.
// Every positive case uses two different invented workflow shapes; every credit has a negative for each piece of its
// evidence. Nothing here is copied from a real project.
import { afterEach, describe, expect, it } from 'vitest';
import { mapCoverage, type Coverage } from '../src/audit/coverage.js';
import { floorNeeds } from '../src/engine/needs.js';
import { creditNotes } from '../src/audit/model.js';
import { applyLastRuns } from '../src/audit/github-signals.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import type { Capabilities, Layer, Need, RepoProfile, Service } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: false,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['test', 'lint'],
  frameworks: [], quality: emptyServiceQuality(), ...over,
});
async function profileOf(dir: string, over: Partial<RepoProfile> = {}): Promise<RepoProfile> {
  return {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services: [svc()],
    terraformDirs: [], hasCompose: false, existingWorkflows: await readWorkflows(dir), precommit: readPrecommit(dir), repoFiles: emptyRepoFiles(), ...over,
  };
}
async function coverage(dir: string, over: Partial<RepoProfile> = {}, opts: Parameters<typeof mapCoverage>[3] = {}): Promise<Coverage[]> {
  const p = await profileOf(dir, over);
  return mapCoverage(p, floorNeeds(p, caps), dir, opts);
}
function row(rows: Coverage[], layer: Layer, id: string, service?: string): Coverage {
  const found = rows.find((r) => r.need.layer === layer && r.need.id === id && (service === undefined || r.need.service === service));
  if (!found) throw new Error(`no ${id} row in ${layer}`);
  return found;
}
const wf = (dir: string, name: string, body: string) => writeIn(dir, `.github/workflows/${name}`, body);
const job = (steps: string, id = 'scan', extra = '') => `jobs:\n  ${id}:\n    runs-on: ubuntu-latest\n${extra}    steps:\n${steps}`;
const run = (cmd: string, extra = '') => `      - run: ${cmd}\n${extra}`;

// two invented tools-and-trigger shapes for the push credit
const SHAPES: { name: string; category: string; files: (dir: string) => void }[] = [
  { name: 'secret scan, push limited to main', category: 'secrets', files: (dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n${job(run('gitleaks detect --redact'))}`) },
  { name: 'static analysis, push to main and a release branch pattern', category: 'sast', files: (dir) => wf(dir, 'checks.yml', `on:\n  push:\n    branches: [main, 'release/**']\n  pull_request:\n    types: [opened, synchronize]\n${job(run('semgrep scan --error'), 'analyse')}`) },
];

describe('push credit: every pull request + every push to the default branch', () => {
  for (const shape of SHAPES) {
    it(`push credit: ${shape.name} → push rows covered with a credit`, async () => {
      const dir = makeTempDir();
      shape.files(dir);
      const rows = await coverage(dir);
      const { category } = shape;
      const push = row(rows, 'push', category, category === 'secrets' ? undefined : 'app');
      const merge = row(rows, 'merge', category, category === 'secrets' ? undefined : 'app');
      expect(merge.status).toBe('covered');
      expect(push).toMatchObject({ status: 'covered', creditKind: 'push-default', by: merge.by, where: merge.where });
      expect(push.credit).toBe('runs on every pull request into main and every push to main');
      expect(push.why).toMatch(/runs on every pull request into main and on every push to main\.$/);
      expect(push).not.toHaveProperty('trigger');
      expect(merge.credit).toBeUndefined();
    });
  }

  const partial = async (files: (dir: string) => void, over: Partial<RepoProfile> = {}, opts: Parameters<typeof mapCoverage>[3] = {}) => {
    const dir = makeTempDir();
    files(dir);
    const rows = await coverage(dir, over, opts);
    return row(rows, 'push', 'secrets');
  };
  const gl = run('gitleaks detect --redact');

  it('push credit: no push trigger on the default branch → no credit', async () => {
    const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [develop]\n${job(gl)}`));
    expect(r.status).toBe('partial');
    expect(r.credit).toBeUndefined();
    const t = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    tags: ['v*']\n${job(gl)}`));
    expect(t.status).toBe('partial');
  });
  it('push credit: a paths filter on push or on the pull request → no credit', async () => {
    expect((await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n    paths: ['src/**']\n${job(gl)}`))).credit).toBeUndefined();
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on:\n  pull_request:\n    paths: ['src/**']\n  push:\n    branches: [main]\n${job(gl)}`);
    const rows = await coverage(dir);
    expect(row(rows, 'merge', 'secrets').status).toBe('partial');
    expect(row(rows, 'push', 'secrets').status).toBe('partial');
  });
  it('push credit: no pull request trigger → no credit', async () => {
    const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  push:\n    branches: [main]\n${job(gl)}`));
    expect(r.status).toBe('partial');
    expect(r.credit).toBeUndefined();
  });
  it('push credit: the pull request cover is a different run than the push hit → no credit', async () => {
    const r = await partial((dir) => {
      wf(dir, 'a.yml', `on:\n  push:\n    branches: [main]\n${job(gl)}`);
      wf(dir, 'b.yml', `on: pull_request\n${job(gl)}`);
    });
    expect(r.status).toBe('partial');
    expect(r.credit).toBeUndefined();
    const sameFileOtherJob = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  one:\n    runs-on: x\n    if: github.event_name == 'push'\n    steps:\n${gl}  two:\n    runs-on: x\n    steps:\n${run('gitleaks detect --redact')}`));
    expect(sameFileOtherJob.credit).toBeUndefined();
  });
  it('push credit: a pull_request branches filter that excludes the default branch → no credit', async () => {
    for (const filter of ["branches: [develop]", "branches-ignore: [main]", "branches: ['release/**']"]) {
      const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n    ${filter}\n  push:\n    branches: [main]\n${job(gl)}`));
      expect(r.status, filter).toBe('partial');
      expect(r.credit, filter).toBeUndefined();
    }
  });
  it('push credit: pull_request types without synchronize → no credit', async () => {
    for (const types of ['[opened]', '[opened, reopened]', '[labeled]']) {
      const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n    types: ${types}\n  push:\n    branches: [main]\n${job(gl)}`));
      expect(r.status, types).toBe('partial');
      expect(r.credit, types).toBeUndefined();
    }
  });
  it('push credit: an if: on the job or on the step → no credit', async () => {
    const cond = "github.actor != 'bot'";
    const shapes = [
      job(gl, 'scan', `    if: ${cond}\n`),
      job(run('gitleaks detect --redact', `        if: ${cond}\n`)),
      job(run('gitleaks detect --redact', "        if: github.event_name == 'push'\n")),
      job(gl, 'scan', "    if: github.event_name == 'pull_request'\n"),
    ];
    for (const body of shapes) {
      const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n${body}`));
      expect(r.credit, body).toBeUndefined();
      expect(r.status, body).not.toBe('covered');
    }
  });
  it('push credit: same file, the pull-request run is another job than the push hit → no credit', async () => {
    // the push-only job comes AFTER the pull-request one, so this fails on the `where` check, not on ordering
    const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  one:\n    runs-on: x\n    if: github.event_name == 'pull_request'\n    steps:\n${gl}  two:\n    runs-on: x\n    if: github.event_name == 'push'\n    steps:\n${gl}`));
    expect(r.credit).toBeUndefined();
  });
  it('push credit: a run that can pass while failing (continue-on-error) → no credit', async () => {
    const r = await partial((dir) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n${job(run('gitleaks detect --redact', '        continue-on-error: true\n'))}`));
    expect(r.status).toBe('partial');
    expect(r.credit).toBeUndefined();
  });
  it('push credit: rate-stop placeholder branch → no credit (both worlds → unknown)', async () => {
    const files = (dir: string) => wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n${job(gl)}`);
    const wide = await partial(files, {}, { branchGuess: 'widest' });
    const narrow = await partial(files, {}, { branchGuess: 'narrowest' });
    expect(narrow.status).toBe('partial');
    expect(narrow.credit).toBeUndefined();
    // the two worlds give different rows, and the audit (model.ts bothWorlds) turns any difference into unknown
    expect(wide.status === narrow.status && wide.why === narrow.why).toBe(false);
    const real = await partial(files);
    expect(real.status).toBe('covered');
    // an empty default branch name is never credited
    expect((await partial(files, { defaultBranch: '' })).credit).toBeUndefined();
  });
  it('push credit: merge row made partial by versionAdjust or lastRunRows → no push credit', async () => {
    // versionAdjust: ESLint 10 does not read .eslintrc, so the lint rows (push and merge) are partial, not covered
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n${job(run('npx eslint .'))}`);
    const quality = { ...emptyServiceQuality(), eslintConfig: 'eslintrc' as const, versions: { eslint: '10.1.0' } };
    const rows = await coverage(dir, { services: [svc({ quality })] });
    expect(row(rows, 'merge', 'lint', 'app').status).toBe('partial');
    expect(row(rows, 'push', 'lint', 'app')).toMatchObject({ status: 'partial' });
    expect(row(rows, 'push', 'lint', 'app').credit).toBeUndefined();
    // lastRunRows: a failed last run turns the credited push row, like any covered row, into partial without its credit
    const ok = makeTempDir();
    wf(ok, 'ci.yml', `on:\n  pull_request:\n  push:\n    branches: [main]\n${job(gl)}`);
    const credited = await coverage(ok);
    const p = await profileOf(ok);
    const listed = new Set(p.existingWorkflows.map((w) => w.path));
    const failed = applyLastRuns(credited, new Map([['.github/workflows/ci.yml', { state: 'read', conclusion: 'failure', createdAt: '2026-11-01T00:00:00Z' } as never]]), listed, 'main').rows;
    const push = row(failed, 'push', 'secrets');
    expect(push.status).toBe('partial');
    expect(push.credit).toBeUndefined();
    expect(push.creditKind).toBeUndefined();
  });
});

// ---------- credit 2: hooks re-run in CI ----------

const hooksFile = (repos: string) => `repos:\n${repos}`;
const eslintHook = '  - repo: https://github.com/pre-commit/mirrors-eslint\n    rev: v9.0.0\n    hooks:\n      - id: eslint\n';
const leakHook = '  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.0.0\n    hooks:\n      - id: gitleaks\n';
const localHook = (id: string, entry: string) => `  - repo: local\n    hooks:\n      - id: ${id}\n        name: ${id}\n        entry: ${entry}\n        language: system\n`;

describe('hooks-ci: CI runs the same tools as the hooks', () => {
  const hooksCi = async (setup: (dir: string) => void, layer: Layer = 'push') => {
    const dir = makeTempDir();
    setup(dir);
    return row(await coverage(dir), layer, 'hooks-ci');
  };
  const SHAPES2: { name: string; setup: (dir: string) => void; tools: string }[] = [
    { name: 'a linter hook run by its own command', tools: 'eslint', setup: (dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook));
      wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .'))}`);
    } },
    { name: 'a secret-scan hook plus a local hook, both run as binaries', tools: 'gitleaks, ', setup: (dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(leakHook + localHook('lint', 'eslint')));
      wf(dir, 'checks.yml', `on: [push, pull_request]\njobs:\n  a:\n    runs-on: x\n    steps:\n${run('gitleaks detect --redact')}  b:\n    runs-on: x\n    steps:\n${run('eslint .')}`);
    } },
  ];
  for (const s of SHAPES2) {
    for (const layer of ['push', 'merge'] as const) {
      it(`hooks-ci: ${s.name} → covered on ${layer}`, async () => {
        const dir = makeTempDir();
        s.setup(dir);
        const r = row(await coverage(dir), layer, 'hooks-ci');
        expect(r).toMatchObject({ status: 'covered', creditKind: 'hooks-ci', by: 'pre-commit' });
        expect(r.credit).toMatch(/^CI runs the same tools as your hooks: /);
        expect(r.credit).toContain(s.tools.split(',')[0] as string);
        expect(r.where).toMatch(/^\.github\/workflows\/[a-z]+\.yml \(job /);
      });
    }
  }
  it('hooks-ci: a tool of the hooks that CI does not run → not covered', async () => {
    const r = await hooksCi((dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook + leakHook));
      wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .'))}`);
    });
    expect(r.status).toBe('missing');
    expect(r.credit).toBeUndefined();
  });
  it('hooks-ci: CI runs the tool on the other trigger only → not covered on this layer', async () => {
    const setup = (dir: string) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook));
      wf(dir, 'ci.yml', `on: pull_request\n${job(run('npx eslint .'))}`);
    };
    expect((await hooksCi(setup, 'push')).status).not.toBe('covered');
    expect((await hooksCi(setup, 'merge')).status).toBe('covered');
  });
  it('hooks-ci: the CI run is conditional, soft or in another folder → not covered', async () => {
    const hook = (dir: string) => writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook));
    expect((await hooksCi((dir) => { hook(dir); wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .', '        continue-on-error: true\n'))}`); })).credit).toBeUndefined();
    expect((await hooksCi((dir) => { hook(dir); wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .', "        if: github.actor == 'x'\n"))}`); })).credit).toBeUndefined();
    expect((await hooksCi((dir) => { hook(dir); wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(`      - run: npx eslint .\n        working-directory: web\n`)}`); })).credit).toBeUndefined();
  });
  it('hooks-ci: CI runs the tool on one folder only, the hook on the whole repo → not covered', async () => {
    const r = await hooksCi((dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook));
      writeIn(dir, 'src/a.js', 'x\n');
      wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint src'))}`);
    });
    expect(r.credit).toBeUndefined();
  });
  it('hooks-ci: the tools run in two workflows → not covered (one workflow holds them all)', async () => {
    const r = await hooksCi((dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook + leakHook));
      wf(dir, 'a.yml', `on: [push, pull_request]\n${job(run('npx eslint .'))}`);
      wf(dir, 'b.yml', `on: [push, pull_request]\n${job(run('gitleaks detect --redact'))}`);
    });
    expect(r.credit).toBeUndefined();
  });
  it('hooks-ci: no hooks found, unreadable config, or a hook pipegen doesn\'t recognise → not covered', async () => {
    const ci = (dir: string) => wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .'))}`);
    // no hooks found: an empty config; CI running a tool must not make the row vacuously covered
    const empty = await hooksCi((dir) => { writeIn(dir, '.pre-commit-config.yaml', 'repos: []\n'); ci(dir); });
    expect(empty.status).toBe('missing');
    // unreadable: not YAML
    const broken = await hooksCi((dir) => { writeIn(dir, '.pre-commit-config.yaml', 'repos: [\n  - : :\n'); ci(dir); });
    expect(broken.status).not.toBe('covered');
    // a hook beside a recognised one that pipegen doesn't know: the row names it and stays uncredited
    const unknown = await hooksCi((dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(eslintHook + localHook('house-rules', './tools/house-rules.sh')));
      ci(dir);
    });
    expect(unknown.status).toBe('missing');
    expect(unknown.why).toContain('house-rules');
    // a look-alike repo's hook (not on pipegen's list) is not recognised either
    const lookalike = await hooksCi((dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile('  - repo: https://example.invalid/mirrors-eslint\n    rev: v1\n    hooks:\n      - id: eslint\n'));
      ci(dir);
    });
    expect(lookalike.status).toBe('missing');
    expect(lookalike.why).toContain('eslint');
  });
  it('hooks-ci: secrets hook with only a never-listed CI action → not covered', async () => {
    const r = await hooksCi((dir) => {
      writeIn(dir, '.pre-commit-config.yaml', hooksFile(leakHook));
      wf(dir, 'ci.yml', `on: [push, pull_request]\n${job('      - uses: gitleaks/gitleaks-action@v2\n')}`);
    });
    expect(r.status).not.toBe('covered');
    expect(r.credit).toBeUndefined();
  });
  it('hooks-ci: husky and lefthook are never credited (free shell cannot be read to the end)', async () => {
    const ci = (dir: string) => wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .'))}`);
    const lefthook = await hooksCi((dir) => { writeIn(dir, 'lefthook.yml', 'pre-commit:\n  commands:\n    lint:\n      run: eslint .\n'); ci(dir); });
    expect(lefthook.status).not.toBe('covered');
    const husky = await hooksCi((dir) => { writeIn(dir, '.husky/pre-commit', 'eslint .\n'); ci(dir); });
    expect(husky.status).not.toBe('covered');
  });
  it('hooks-ci: no hook manager → untouched', async () => {
    const r = await hooksCi((dir) => wf(dir, 'ci.yml', `on: [push, pull_request]\n${job(run('npx eslint .'))}`));
    expect(r.status).toBe('missing');
    expect(r.why).not.toContain('Not counted');
  });
});

// ---------- credit 4: signing for a target with no image ----------

describe('signing credit: cosign sign-blob on a release without an image', () => {
  const signingNeed: Need = { id: 'signing-app', layer: 'deploy', category: 'signing', service: 'app', why: '', blocking: false, floor: false };
  const sign = async (steps: string, on: string, noImage: boolean) => {
    const dir = makeTempDir();
    wf(dir, 'release.yml', `on: ${on}\n${job(steps, 'publish')}`);
    const p = await profileOf(dir);
    return (await mapCoverage(p, [signingNeed], dir, { noImage: () => noImage }))[0] as Coverage;
  };
  it('signing credit: sign-blob in two invented release shapes → covered with a credit', async () => {
    for (const [steps, on] of [
      [run('cosign sign-blob --yes dist/pkg.tgz --output-signature dist/pkg.sig'), "\n  push:\n    tags: ['v*']"],
      [`${run('make dist')}${run('cosign sign-blob --key env://K --yes out/artifact.zip')}`, '\n  release:\n    types: [published]'],
    ] as [string, string][]) {
      const r = await sign(steps, on, true);
      expect(r).toMatchObject({ status: 'covered', by: 'cosign', creditKind: 'signing' });
      expect(r.credit).toContain('cosign');
    }
  });
  it('signing credit: no cosign step, or a target that builds an image → no credit', async () => {
    const none = await sign(run('make dist'), '\n  release:\n    types: [published]', true);
    expect(none.status).not.toBe('covered');
    expect(none.credit).toBeUndefined();
    const image = await sign(run('cosign sign-blob x'), '\n  release:\n    types: [published]', false);
    expect(image.credit).toBeUndefined();
  });
  it('signing credit: cosign verify or a help call is not a signature → no credit', async () => {
    const r = await sign(run('cosign verify-blob --key k --signature s f'), '\n  release:\n    types: [published]', true);
    expect(r.status).not.toBe('covered');
  });
});

describe('credit notes (S17 and the push warning)', () => {
  const rowOf = (creditKind: Coverage['creditKind'], status: Coverage['status'] = 'covered'): Coverage => ({ need: { id: 'x', layer: 'push', category: 'x', why: '', blocking: true, floor: false }, status, why: 'w', ...(creditKind === undefined ? {} : { creditKind }) });
  it('a covered push credit adds the warning; a partial one (after a failed run) does not', () => {
    const p = { private: false } as RepoProfile;
    expect(creditNotes([rowOf('push-default')], p)).toEqual(["Pushes to branches without a pull request aren't checked."]);
    expect(creditNotes([rowOf('push-default', 'partial')], p)).toEqual([]);
    expect(creditNotes([rowOf('signing')], p)).toEqual([]);
  });
  it('a signing credit on a private repo adds the keyless note, on a public repo not', () => {
    expect(creditNotes([rowOf('signing')], { private: true } as RepoProfile)[0]).toContain('public Sigstore log');
    expect(creditNotes([rowOf('hooks-ci')], { private: true } as RepoProfile)).toEqual([]);
  });
});

// ---------- credit 3: the deploy gate the repo already has (J3b, ruling B3, pre-flight §4 item 2 (a)-(h)) ----------
// The property: every deploying job runs only after CI passed, on the default branch, for the exact commit CI tested,
// from this repo (never a fork's run). Two accepted forms: (a) a guarded workflow_run deploy with a commit check, (b) a
// deploy job inside the CI workflow that needs every CI job and runs only on a push to the default branch. All the
// shapes below are invented.

const HEAD = '${{ github.event.workflow_run.head_sha }}';
const CO = '      - uses: actions/checkout@v4\n';
const coRef = (ref: string) => `      - uses: actions/checkout@v4\n        with:\n          ref: ${ref}\n`;
const GUARD = "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push' && github.event.workflow_run.head_repository.full_name == github.repository";
const GUARD_TURNED = "github.repository == github.event.workflow_run.head_repository.full_name && 'push' == github.event.workflow_run.event && (github.event.workflow_run.conclusion == 'success')";
const ciFile = (name = 'CI', on = '\n  push:\n    branches: [main]\n  pull_request:', steps = '      - run: npm test\n') =>
  `name: ${name}\non:${on}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n${CO}${steps}`;
const CHECKS = `name: Checks\non:\n  push:\n    branches: [main]\n  pull_request:\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npx eslint .\n  unit:\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npm test\n`;
/** A commit check step: `if [ <current> != <tested> ]; then …; exit 1; fi`, the tested SHA through env var TESTED. */
const checkStep = (o: { env?: string; current?: string; extra?: string } = {}) =>
  `      - name: same commit as CI\n${o.extra ?? ''}        env:\n          TESTED: ${o.env ?? HEAD}\n        run: |\n          if [ "${o.current ?? '$(git rev-parse HEAD)'}" != "$TESTED" ]; then\n            echo ::error::not the commit CI tested\n            exit 1\n          fi\n`;
/** Shape A: the guard and the commit check on the first job, the deploy job through needs (the evidence shape, B3). */
const deployA = (o: { guard?: string; check?: string; on?: string; deployIf?: string; verifyExtra?: string; deploySteps?: string; workflows?: string; before?: string } = {}) =>
  `name: Deploy\non:\n  workflow_run:\n    workflows: [${o.workflows ?? 'CI'}]\n    types: [completed]\n${o.on ?? ''}jobs:\n  verify:\n    if: ${o.guard ?? GUARD}\n${o.verifyExtra ?? ''}    runs-on: ubuntu-latest\n    steps:\n${CO}${o.before ?? ''}${o.check ?? checkStep()}      - run: npm run build\n  deploy:\n    needs: verify\n${o.deployIf === undefined ? '' : `    if: ${o.deployIf}\n`}    runs-on: ubuntu-latest\n    environment: production\n    steps:\n${o.deploySteps ?? `${CO}      - run: npx wrangler deploy\n`}`;
/** Shape B: one job, the guard as one ${{ }} expression in another order, the tested commit checked out by ref. */
const deployB = (o: { branches?: string | null; ref?: string; guard?: string; extraOn?: string } = {}) =>
  `on:\n  workflow_run:\n    workflows: ["Checks"]\n${o.branches === null ? '' : `    branches: [${o.branches ?? 'main'}]\n`}${o.extraOn ?? ''}jobs:\n  ship:\n    if: \${{ ${o.guard ?? GUARD_TURNED} }}\n    runs-on: ubuntu-latest\n    steps:\n${coRef(o.ref ?? HEAD)}      - run: ./scripts/publish-site.sh\n`;
/** Shape C: three jobs (gate → build → release), the guard folded over lines, a one-line test against GITHUB_SHA. */
const deployC = (o: { gateSteps?: string; buildIf?: string } = {}) =>
  `name: Ship it\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  gate:\n    if: >-\n      github.event.workflow_run.event == 'push' &&\n      github.event.workflow_run.conclusion == 'success' &&\n      github.event.workflow_run.head_repository.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n${o.gateSteps ?? '      - run: test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}"\n'}  build:\n    needs: gate\n${o.buildIf === undefined ? '' : `    if: ${o.buildIf}\n`}    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npm ci && npm run build\n  release:\n    needs: [gate, build]\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: flyctl deploy --remote-only\n`;

async function gateRows(files: Record<string, string>, over: Partial<RepoProfile> = {}, opts: Parameters<typeof mapCoverage>[3] = {}): Promise<Coverage[]> {
  const dir = makeTempDir();
  for (const [name, body] of Object.entries(files)) wf(dir, name, body);
  return (await coverage(dir, over, opts)).filter((r) => r.need.category === 'deploy-verify');
}
async function gateOf(files: Record<string, string>, over: Partial<RepoProfile> = {}, opts: Parameters<typeof mapCoverage>[3] = {}): Promise<Coverage> {
  const rows = await gateRows(files, over, opts);
  expect(rows.length).toBeGreaterThan(0);
  return rows[0] as Coverage;
}
const expectMissing = (r: Coverage, label?: string) => {
  expect(r.status, label).toBe('missing');
  expect(r.credit, label).toBeUndefined();
  expect(r.creditKind, label).toBeUndefined();
};
const expectGated = (r: Coverage, label?: string) => {
  expect(r.status, label).toBe('covered');
  expect(r.creditKind, label).toBe('deploy-gate');
  expect(r.credit, label).toBe("deploys run only after CI passed on main, for the commit CI tested, never for a fork's run");
};

// the positive shapes of form (a): [CI files, deploy files]
const GATED: { name: string; files: Record<string, string> }[] = [
  { name: 'guard and env-var check on the first job, deploy through needs', files: { 'ci.yml': ciFile(), 'deploy.yml': deployA() } },
  { name: 'one job, guard in another order, checkout by ref, branches: [main]', files: { 'checks.yml': CHECKS, 'release-site.yml': deployB() } },
  { name: 'three jobs, folded guard, one-line test against GITHUB_SHA', files: { 'ci.yml': ciFile(), 'deploy.yml': deployC() } },
];

describe('deploy gate (a): a guarded workflow_run deploy with a commit check', () => {
  it('guard on the root job, deploy job gated through needs → covered', async () => {
    for (const shape of GATED) {
      const r = await gateOf(shape.files);
      expectGated(r, shape.name);
      expect(r.why, shape.name).toMatch(/^Every deploy runs only after CI passed on main, for the commit CI tested, and never for a fork's run/);
      expect(r.where, shape.name).toMatch(/^\.github\/workflows\/(deploy|release-site)\.yml$/);
      expect(r.why, shape.name).toContain(shape.files['ci.yml'] === undefined ? '.github/workflows/checks.yml' : '.github/workflows/ci.yml');
    }
  });

  it('workflow_run deploy without push/same-repo guard → deploy-verify missing', async () => {
    // Review Focus #4: a fork's pull-request run of CI can trigger it
    const noPush = "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.head_repository.full_name == github.repository";
    const noRepo = "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'";
    const noConclusion = "github.event.workflow_run.event == 'push' && github.event.workflow_run.head_repository.full_name == github.repository";
    const branchOnly = "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.head_branch == 'main'";
    // a `!=` term never counts as a guard (fix round 1, review I1)
    const notPr = GUARD.replace("github.event.workflow_run.event == 'push'", "github.event.workflow_run.event != 'pull_request'");
    const notOtherRepo = GUARD.replace('github.event.workflow_run.head_repository.full_name == github.repository', "github.event.workflow_run.head_repository.fork != true");
    const notPush = GUARD.replace("github.event.workflow_run.event == 'push'", "github.event.workflow_run.event != 'push'");
    const notSuccess = GUARD.replace("github.event.workflow_run.conclusion == 'success'", "github.event.workflow_run.conclusion != 'success'");
    for (const guard of [noPush, noRepo, noConclusion, branchOnly, notPr, notOtherRepo, notPush, notSuccess]) {
      expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard }) }), guard);
      expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ guard }) }), guard);
    }
    // no guard at all
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard: 'true' }) }));
    // the guards compared with the wrong values
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard: GUARD.replace("'push'", "'pull_request'") }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard: GUARD.replace("'success'", "'failure'") }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard: GUARD.replace('github.repository', "'someone/else'") }) }));
    // a guard that only looks like one: the comparison hides inside a parenthesised operand, or in a string
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard: GUARD.replace("== 'push'", "== ('push' && github.actor)") }) }));
    // double-quoted strings are not GitHub expression strings
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ guard: `\${{ ${GUARD.replace(/'/g, '"')} }}` }) }));
  });

  it('a stray job without the guard, or the guard on a step only → missing', async () => {
    const stray = `${deployA()}  notify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo done\n`;
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': stray }));
    const stepGuard = deployA({ guard: 'true', check: `${checkStep()}`, deploySteps: `${CO}      - if: ${GUARD}\n        run: npx wrangler deploy\n` });
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': stepGuard }));
  });

  it('a job on the chain with always(), !cancelled() or || → missing', async () => {
    for (const deployIf of ['always()', '${{ !cancelled() }}', "success() || github.event_name == 'workflow_dispatch'", "${{ always() && github.event.workflow_run.event == 'push' }}",
      'failure()', 'cancelled()', 'success() == false', "contains(github.event.workflow_run.event, 'push')", '${{ !success() }}', "${{ !(github.event.workflow_run.conclusion == 'success') }}",
      'success() != false', "vars.TARGET != '' && always()", "${{ !cancelled() && vars.TARGET != '' }}"]) {
      expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ deployIf }) }), deployIf);
      expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ buildIf: deployIf }) }), deployIf);
    }
    // a plain extra condition only narrows the run: still covered (fix round 1, review I1: `!=` terms too)
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ deployIf: "vars.SITE_PROJECT != '' && vars.SITE_URL != ''" }) }));
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ buildIf: "${{ github.actor != 'release-bot' && (github.event.workflow_run.head_branch != 'wip') }}" }) }));
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ deployIf: "success() && github.event.workflow_run.head_branch == 'main'" }) }));
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ buildIf: 'success()' }) }));
    // continue-on-error on a job of the chain: a failed check counts as passed for the jobs that need it
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ verifyExtra: '    continue-on-error: true\n' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ verifyExtra: '    continue-on-error: ${{ github.event.workflow_run.event == \'push\' }}\n' }) }));
  });

  it('SHA check step with if: or continue-on-error → missing', async () => {
    for (const extra of ["        if: github.event.workflow_run.event == 'push'\n", '        if: always()\n', '        continue-on-error: true\n']) {
      expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: checkStep({ extra }) }) }), extra);
    }
    // the step after a failed check that still runs (a status function) → missing
    const after = deployA({ check: `${checkStep()}      - if: always()\n        run: npx wrangler deploy\n` });
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': after }));
    // the check after a build step, or with no exit on a mismatch, or in a shell that doesn't stop → missing
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ before: '      - run: npm run build\n' }) }));
    const echoOnly = '      - env:\n          TESTED: ${{ github.event.workflow_run.head_sha }}\n        run: |\n          if [ "$(git rev-parse HEAD)" != "$TESTED" ]; then\n            echo ::warning::not the tested commit\n          fi\n';
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: echoOnly }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: checkStep({ extra: '        shell: pwsh\n' }) }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}" || true\n' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: |\n          exit 0\n          test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}"\n' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: test $GITHUB_SHA = ${{ github.event.workflow_run.head_sha }}\n        shell: bash {0}\n' }) }));
    // a build step before the check, also with a check that doesn't depend on the checkout (GITHUB_SHA)
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: `${CO}      - run: npm ci\n      - run: test "$GITHUB_SHA" = "\${{ github.event.workflow_run.head_sha }}"\n` }) }));
    // the check in a job that a build job of the chain doesn't wait for (they run side by side)
    const sideBySide = deployC().replace('  build:\n    needs: gate\n', `  build:\n    if: ${GUARD}\n`);
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': sideBySide }));
    // GITHUB_SHA set by the workflow itself is not the commit GitHub checked out
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': `env:\n  GITHUB_SHA: ${HEAD}\n${deployC()}` }));
    // no check at all, and a plain checkout: the default branch's newest commit, maybe not the one CI tested
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: '' }) }));
  });

  it('SHA via env var set to exactly head_sha → covered; any other env value → missing', async () => {
    // two shapes: the step's env (shape A) and the job's env with GITHUB_SHA on the other side (shape A, job level)
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: checkStep({ env: '${{github.event.workflow_run.head_sha}}' }) }) }));
    const jobEnv = deployA({ verifyExtra: `    env:\n      WANT: ${HEAD}\n`, check: '      - run: \'[ "$GITHUB_SHA" == "${WANT}" ]\'\n' });
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': jobEnv }));
    for (const env of ['${{ github.event.workflow_run.head_branch }}', '${{ github.sha }}', '${{ github.event.workflow_run.head_sha }}x', 'abc123', '${{ inputs.sha }}',
      '${{ github.event.workflow_run.head_commit.id }}', '"${{ github.event.workflow_run.head_sha }} "']) {
      expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: checkStep({ env }) }) }), env);
    }
    // the step's env wins over the job's: a job-level head_sha under a step-level other value is not the check
    const shadowed = deployA({ verifyExtra: `    env:\n      TESTED: ${HEAD}\n`, check: checkStep({ env: '${{ github.sha }}' }) });
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': shadowed }));
    // comparing the tested SHA with itself proves nothing
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: checkStep({ current: '$TESTED' }) }) }));
  });

  it('ref: head_sha without branches: [<default>] → missing', async () => {
    for (const branches of [null, 'main, develop', "'**'", "'mai*'"]) {
      expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ branches }) }), String(branches));
    }
    expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ extraOn: "    branches-ignore: ['wip/**']\n" }) }));
    // a checkout of another ref, and a check made trivial by checking out the tested commit first
    expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ ref: 'main' }) }));
    expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ ref: '${{ github.event.workflow_run.head_branch }}' }) }));
    const trivial = deployA({ check: `${coRef(HEAD)}${checkStep()}` });
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': trivial }));
    // with branches: [main] and every checkout taking the tested commit, a two-job shape is the ref form
    const refTwoJobs = `on:\n  workflow_run:\n    workflows: [CI]\n    branches: [main]\njobs:\n  build:\n    if: ${GUARD}\n    runs-on: ubuntu-latest\n    steps:\n${coRef(HEAD)}      - run: npm run build\n  deploy:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n${coRef(HEAD)}      - run: npx wrangler deploy\n`;
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': refTwoJobs }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': refTwoJobs.replace(/(deploy:[\s\S]*)ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}\n/, '$1ref: ${{ github.sha }}\n') }));
    // the checkout of another repository
    const other = deployA({ deploySteps: `${CO}        with:\n          repository: someone/else\n      - run: npx wrangler deploy\n` });
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': other }));
  });

  it('ref form: CI that runs on tag pushes, or a branches filter in another letter case → missing (review M1, S-b)', async () => {
    // a tag named like the default branch has that name as head_branch
    const tagged = CHECKS.replace('    branches: [main]\n', "    branches: [main]\n    tags: ['*']\n");
    expectMissing(await gateOf({ 'checks.yml': tagged, 'release-site.yml': deployB() }));
    expectMissing(await gateOf({ 'checks.yml': CHECKS.replace('  push:\n    branches: [main]\n', '  push:\n'), 'release-site.yml': deployB() }));
    expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ branches: 'Main' }) }));
    // the check-step form doesn't depend on branch names: the run's own commit is the default branch's
    expectGated(await gateOf({ 'ci.yml': ciFile('CI', "\n  push:\n    tags: ['*']\n    branches: [main]"), 'deploy.yml': deployA() }));
  });

  it('commit check script with an open quote or here-document → missing (security review S-a)', async () => {
    // shape 1: an echo opens a string that runs over the check, which then never runs
    const swallowedIf = '      - env:\n          TESTED: ${{ github.event.workflow_run.head_sha }}\n        run: |\n          echo "checking\n          if [ "$GITHUB_SHA" != "$TESTED" ]; then\n            exit 1\n          fi\n          "\n';
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: swallowedIf }) }));
    // shape 2: the exit inside the then-block is swallowed by a string opened on the echo line
    const swallowedExit = '      - env:\n          TESTED: ${{ github.event.workflow_run.head_sha }}\n        run: |\n          if [ "$GITHUB_SHA" != "$TESTED" ]; then\n            echo \'mismatch\n            exit 1\n          fi\n          \'\n          fi\n';
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: swallowedExit }) }));
    // shape 3: a one-line test after a here-document opener, and a quote in the || block
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: |\n          cat <<EOF\n          test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}"\n          EOF\n' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}" || { echo "bad; exit 1; }\n' }) }));
    // an echo line with quotes is refused even when they close, and a quote or here-document left open after the check
    // refuses the whole script
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: checkStep().replace('echo ::error::not the commit CI tested', 'echo "not the commit CI tested"') }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: |\n          test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}"\n          echo "done\n' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: |\n          test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}"\n          cat <<EOF > out.txt\n          x\n          EOF\n' }) }));
    // the same checks without quotes in the echo lines are credited
    const plain = '      - env:\n          TESTED: ${{ github.event.workflow_run.head_sha }}\n        run: |\n          # don\'t deploy another commit\n          echo checking\n          if [ "$GITHUB_SHA" != "$TESTED" ]; then\n            echo ::error::mismatch\n            exit 1\n          fi\n';
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ check: plain }) }));
    expectGated(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployC({ gateSteps: '      - run: test "$GITHUB_SHA" = "${{ github.event.workflow_run.head_sha }}" || { echo mismatch; exit 1; }\n' }) }));
  });

  it('deploy job is a reusable call → missing', async () => {
    const callee = 'on: workflow_call\njobs:\n  steps:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n';
    const local = deployA().replace(/  deploy:\n[\s\S]*$/, '  deploy:\n    needs: verify\n    uses: ./.github/workflows/steps.yml\n');
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': local, 'steps.yml': callee }));
    const remote = deployA().replace(/  deploy:\n[\s\S]*$/, `  deploy:\n    needs: verify\n    uses: some-org/infra/.github/workflows/deploy.yml@${'a'.repeat(40)}\n`);
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': remote }));
    // a guarded reusable call beside the gated deploy (not on its chain): it may deploy too
    const beside = `${deployA()}  notify:\n    if: ${GUARD}\n    uses: ./.github/workflows/steps.yml\n`;
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': beside, 'steps.yml': callee }));
  });

  it('other triggers in the deploy file → missing', async () => {
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ on: '  workflow_dispatch:\n' }) }));
    expectMissing(await gateOf({ 'checks.yml': CHECKS, 'release-site.yml': deployB({ extraOn: '  push:\n    branches: [main]\n' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ on: '  workflow_call:\n' }) }));
  });

  it('workflows: [ci] names no workflow, or two → missing', async () => {
    // no workflow of that name (a name is matched, never a file name)
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ workflows: 'ci-typo' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ workflows: '.github/workflows/ci.yml' }) }));
    // two workflows of that name
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'ci-nightly.yml': ciFile(), 'deploy.yml': deployA() }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'other.yml': ciFile('ci'), 'deploy.yml': deployA() }));
    // two names in the list, or a pattern
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'lint.yml': ciFile('Lint'), 'deploy.yml': deployA({ workflows: 'CI, Lint' }) }));
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA({ workflows: "'C*'" }) }));
    // the deploy workflow itself
    expectMissing(await gateOf({ 'ci.yml': ciFile('Build'), 'deploy.yml': deployA().replace('name: Deploy', 'name: CI') }));
    // the named workflow doesn't run on a push to the default branch, or runs no check
    expectMissing(await gateOf({ 'ci.yml': ciFile('CI', '\n  pull_request:'), 'deploy.yml': deployA() }));
    expectMissing(await gateOf({ 'ci.yml': ciFile('CI', '\n  push:\n    branches: [develop]'), 'deploy.yml': deployA() }));
    expectMissing(await gateOf({ 'ci.yml': ciFile('CI', undefined, '      - run: echo ok\n'), 'deploy.yml': deployA() }));
  });
});

describe('deploy gate (b): a deploy job inside the CI workflow', () => {
  const ci2 = (o: { on?: string; deployIf?: string | null; needs?: string; deployExtra?: string; lintExtra?: string } = {}) =>
    `name: Pipeline\non:${o.on ?? '\n  push:\n    branches: [main]\n  pull_request:'}\njobs:\n  lint:\n    runs-on: ubuntu-latest\n${o.lintExtra ?? ''}    steps:\n${CO}      - run: npx eslint .\n  test:\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npm test\n  deploy:\n    needs: ${o.needs ?? '[lint, test]'}\n${o.deployIf === null ? '' : `    if: ${o.deployIf ?? "github.ref == 'refs/heads/main' && github.event_name == 'push'"}\n`}    runs-on: ubuntu-latest\n    steps:\n${o.deployExtra ?? CO}      - run: npx vercel deploy --prod\n`;
  // a push-only workflow: unit → e2e → publish, no if: needed
  const ci3 = (o: { on?: string; publishNeeds?: string } = {}) =>
    `on:${o.on ?? '\n  push:\n    branches: [main]'}\njobs:\n  unit:\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npm test\n  e2e:\n    needs: unit\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npm run e2e\n  publish:\n    needs: ${o.publishNeeds ?? 'e2e'}\n    runs-on: ubuntu-latest\n    environment: prod\n    steps:\n${CO}      - run: ./deploy.sh\n`;

  it('deploy gate (b): deploy job needs every CI job and runs only on a push to main → covered', async () => {
    for (const [name, files] of [['pull request + push, guarded deploy job', { 'pipeline.yml': ci2() }], ['push to main only, chain of needs', { 'build.yml': ci3() }],
      ['the ref guard alone', { 'pipeline.yml': ci2({ deployIf: "${{ github.ref == 'refs/heads/main' }}" }) }],
      ['the push-event guard and a != term', { 'pipeline.yml': ci2({ deployIf: "github.event_name == 'push' && vars.HOST != ''" }) }]] as [string, Record<string, string>][]) {
      const r = await gateOf(files);
      expectGated(r, name);
      expect(r.why, name).toMatch(/deploys only on a push to main, after every other job of the same run passed/);
    }
  });

  it('deploy gate (b): another default branch name → the guard must name that branch', async () => {
    const trunk = ci2({ on: '\n  push:\n    branches: [trunk]\n  pull_request:', deployIf: "github.ref == 'refs/heads/trunk'" });
    const r = await gateOf({ 'pipeline.yml': trunk }, { defaultBranch: 'trunk' });
    expect(r).toMatchObject({ status: 'covered', creditKind: 'deploy-gate', credit: "deploys run only after CI passed on trunk, for the commit CI tested, never for a fork's run" });
    expectMissing(await gateOf({ 'pipeline.yml': ci2() }, { defaultBranch: 'trunk' }));
  });

  it('deploy gate (b): a branch named like the default branch in another letter case never counts (security review S-b)', async () => {
    // GitHub's == ignores case, so `github.ref == 'refs/heads/main'` holds for a push to `Main` too: the push trigger itself must be [main]
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ on: '\n  push:\n  pull_request:' }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ on: '\n  push:\n    branches: [main, Main]\n  pull_request:' }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ on: "\n  push:\n    branches: ['*']\n  pull_request:" }) }));
    expectMissing(await gateOf({ 'build.yml': ci3({ on: '\n  push:\n    branches: [Main]' }) }));
    expectMissing(await gateOf({ 'build.yml': ci3({ on: "\n  push:\n    branches-ignore: ['wip/**']" }) }));
  });

  it('deploy gate (b): a CI job the deploy job does not need → missing', async () => {
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ needs: 'test' }) }));
    expectMissing(await gateOf({ 'build.yml': ci3({ publishNeeds: 'unit' }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ needs: '[lint, test, nope]' }) }));
  });

  it('deploy gate (b): no push-to-main guard, a ref_name guard, or another trigger → missing', async () => {
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ deployIf: null }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ deployIf: "github.ref_name == 'main'" }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ deployIf: "github.ref == 'refs/heads/main' || github.event_name == 'push'" }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ deployIf: "github.ref == 'refs/heads/develop'" }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ on: '\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:' }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ on: '\n  push:\n    branches: [main]\n  pull_request_target:' }) }));
    // push-only but with tags too: a tag push is not the default branch
    expectMissing(await gateOf({ 'build.yml': ci3({ on: "\n  push:\n    branches: [main]\n    tags: ['v*']" }) }));
    expectMissing(await gateOf({ 'build.yml': ci3({ on: '\n  push:' }) }));
  });

  it('deploy gate (b): another commit checked out, a soft CI job, or no CI job → missing', async () => {
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ deployExtra: coRef('main') }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ lintExtra: '    continue-on-error: true\n' }) }));
    expectMissing(await gateOf({ 'pipeline.yml': ci2({ lintExtra: '    if: always()\n' }) }));
    const alone = `on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npx vercel deploy --prod\n`;
    expectMissing(await gateOf({ 'deploy.yml': alone }));
    const noCheck = ci3().replace('npm test', 'echo ok').replace('npm run e2e', 'echo ok');
    expectMissing(await gateOf({ 'build.yml': noCheck }));
  });
});

describe('deploy gate: every deploying workflow, per service (h)', () => {
  const two = [svc({ name: 'api', path: 'api', scripts: ['test', 'start'] }), svc({ name: 'web', path: 'web', scripts: ['test', 'start'] })];

  it('a second deploying workflow without the gate → every deploy-verify row missing', async () => {
    const gated = await gateRows({ 'ci.yml': ciFile(), 'deploy.yml': deployA() }, { services: two });
    expect(gated.map((r) => r.need.service).sort()).toEqual(['api', 'web']);
    for (const r of gated) expectGated(r, r.need.service);
    const ungated = `on:\n  push:\n    branches: [main]\njobs:\n  docs:\n    runs-on: ubuntu-latest\n    steps:\n${CO}      - run: npx netlify deploy --prod\n`;
    for (const extra of [{ 'docs-site.yml': ungated }, { 'release-site.yml': deployB({ branches: null }), 'checks.yml': CHECKS }] as Record<string, string>[]) {
      const rows = await gateRows({ 'ci.yml': ciFile(), 'deploy.yml': deployA(), ...extra }, { services: two });
      expect(rows).toHaveLength(2);
      for (const r of rows) expectMissing(r, r.need.service);
    }
    // two gated deploy workflows of both forms: covered, and both are named
    const both = await gateRows({ 'ci.yml': ciFile(), 'deploy.yml': deployA(), 'checks.yml': CHECKS, 'release-site.yml': deployB() }, { services: two });
    for (const r of both) {
      expectGated(r, r.need.service);
      expect(r.where).toBe('.github/workflows/deploy.yml, .github/workflows/release-site.yml');
    }
  });

  it('deploy gate: no deploying workflow, an unreadable workflow, or a rate-stop placeholder branch → no credit', async () => {
    // deploy-verify rows from a runnable service, with no deploying workflow at all
    expectMissing(await gateOf({ 'ci.yml': ciFile() }, { services: [svc({ scripts: ['test', 'start'] })] }));
    // a workflow pipegen couldn't read (readWorkflows skipped it)
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA() }, {}, { skippedWorkflows: 1 }));
    // a listed workflow pipegen can't read again
    const dir = makeTempDir();
    wf(dir, 'ci.yml', ciFile());
    wf(dir, 'deploy.yml', deployA());
    const listed = await readWorkflows(dir);
    const goneWorkflow = { ...(listed[0] as (typeof listed)[number]), path: '.github/workflows/gone.yml', deploys: false };
    const gone = (await coverage(dir, { existingWorkflows: [...listed, goneWorkflow] }))
      .filter((r) => r.need.category === 'deploy-verify');
    expect(gone.length).toBeGreaterThan(0);
    for (const r of gone) expectMissing(r);
    // a rate stop: the narrow world never credits, so the two worlds differ and the audit says unknown
    const narrow = await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA() }, {}, { branchGuess: 'narrowest' });
    expectMissing(narrow);
    // also when CI takes every push, so the narrow bound would read it as taking the default branch
    expectMissing(await gateOf({ 'ci.yml': ciFile('CI', '\n  push:\n  pull_request:'), 'deploy.yml': deployA() }, {}, { branchGuess: 'narrowest' }));
    const wide = await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA() }, {}, { branchGuess: 'widest' });
    expect(wide.status === narrow.status && wide.why === narrow.why).toBe(false);
    expectMissing(await gateOf({ 'ci.yml': ciFile(), 'deploy.yml': deployA() }, { defaultBranch: '' }));
  });
});
