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
