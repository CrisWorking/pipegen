import { afterEach, describe, expect, it, vi } from 'vitest';
import { mapCoverage } from '../src/audit/coverage.js';
import { floorNeeds } from '../src/engine/needs.js';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, RepoProfile } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

// Counts every YAML parse by its text, to prove a local file is parsed once per mapCoverage call however often it is used.
const parses = vi.hoisted(() => ({ texts: [] as string[] }));
vi.mock('../src/read/limits.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/read/limits.js')>();
  return { ...a, parseYamlLimited: (text: string) => (parses.texts.push(text), a.parseYamlLimited(text)) };
});
afterEach(cleanupRepos);

const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: false,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};

describe('mapCoverage reads a local action once', () => {
  it('a composite action used by many steps and jobs is parsed once, not once per use', async () => {
    const dir = makeTempDir();
    const action = 'runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n# marker-action\n';
    writeIn(dir, '.github/actions/a/action.yml', action);
    const steps = '      - uses: ./.github/actions/a\n'.repeat(30);
    const jobs = Array.from({ length: 5 }, (_, i) => `  j${i}:\n    runs-on: x\n    steps:\n${steps}`).join('');
    writeIn(dir, '.github/workflows/w.yml', `on: [pull_request]\njobs:\n${jobs}`);
    const p: RepoProfile = {
      owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
      services: [], terraformDirs: [], hasCompose: false,
      existingWorkflows: await readWorkflows(dir), precommit: readPrecommit(dir), repoFiles: emptyRepoFiles(),
    };
    parses.texts.length = 0;
    await mapCoverage(p, floorNeeds(p, caps), dir);
    expect(parses.texts.filter((t) => t === action)).toHaveLength(1);
  });
});
