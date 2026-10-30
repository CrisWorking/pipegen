// D0b: the CODEOWNERS judge checks the block's meaning with the gate's parser even when the builder agrees with the file. If the builder
// ever translated a path wrongly, byte equality with its output would pass; this is the net under it. The builder is replaced here.
import { describe, expect, it, vi } from 'vitest';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { CreatedFile, PipelineDraft } from '../src/types.js';
import { profile, reviewedList, service } from './helpers/render.js';

const mode = vi.hoisted(() => ({ value: 'translate' as 'translate' | 'own-src' }));

vi.mock('../src/engine/created-builders.js', async (orig) => {
  const real = await orig<typeof import('../src/engine/created-builders.js')>();
  return {
    ...real,
    // a wrong translation: the any-depth names are anchored to the root, and the workflow folder loses its subtree
    codeownersBlock: (paths: readonly string[], owners: readonly string[]) => {
      const b = real.codeownersBlock(paths, owners);
      if (mode.value === 'own-src') return b.replace('# pipegen:end', `src/ ${owners.join(' ')}\n# pipegen:end`);   // owns more than the protected set
      return b.replace('\nvitest.config.* ', '\n/vitest.config.* ').replace('/.github/workflows/ ', '/.github/workflows/* ');
    },
  };
});

const { createdFileProblems } = await import('../src/engine/created-files.js');
const { codeownersBlock, codeownersFile, codeownersProtectedPaths } = await import('../src/engine/created-builders.js');

describe('codeowners judge: the semantic net under the builder', () => {
  const verdictFor = () => {
    const reviewed = reviewedList();
    const draft: PipelineDraft = {
      profile: { ...profile([service({ name: 'root', path: '.' })]), repoFiles: emptyRepoFiles() },
      capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true },
      needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
      codeOwners: { owners: ['@alice', '@bob'], writers: 2 },
    };
    const f: CreatedFile = { path: '.github/CODEOWNERS', content: codeownersFile('', codeownersBlock(codeownersProtectedPaths(draft, reviewed), draft.codeOwners?.owners ?? [])), part: 'codeowners', reason: 't', repo: 'app', edited: { original: '' } };
    return createdFileProblems(f, draft, undefined, { reviewed, inputs: {} }).problems.join(' ');
  };
  it('a block the builder wrote wrongly is refused although the file equals it', () => {
    mode.value = 'translate';
    expect(verdictFor()).toMatch(/gate would not read/);
  });
  it('a block that owns files outside the protected set is refused', () => {
    mode.value = 'own-src';
    expect(verdictFor()).toMatch(/not protected/);
  });
});
