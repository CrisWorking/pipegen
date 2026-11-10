// G17-F1 (sec I1, spec-1 M3, spec-2 I2): the workflows pipegen really assembles (assemble() at head, the layouts of test/assemble.test.ts),
// for the readers that must work on them (keys.ts workflowSecretNames): a public app, a private app (central layout) and a private key-env
// app with a published image (its sign workflow and the deploy layer's image-publish job).
import { createHash } from 'node:crypto';
import { floorNeeds } from '../../src/engine/needs.js';
import { assemble, type AssembleOpts } from '../../src/layers/assemble.js';
import { releaseJobs } from '../../src/layers/deploy.js';
import type { Job } from '../../src/layers/jobs.js';
import type { Capabilities, CreatedFile, ReviewedTool, SigningPlan } from '../../src/types.js';
import { CAPS, node, p, planned, profileOf } from './assemble.js';
import { REVIEWED } from './debate-fixtures.js';

const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
export const REAL_PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const KE_CAPS: Capabilities = { ...CAPS, environments: true, deploymentBranchPolicies: true };

type Planned = ReturnType<typeof planned>;
const lay = (x: Planned, over: Partial<AssembleOpts> = {}): CreatedFile[] => assemble(x.draft, {
  gate: GATE, reviewed: REVIEWED, platform: p, mode: 'none', layout: x.draft.profile.private ? 'central' : 'local', plan: x.plan, ...over,
}).files;

/** A private key-env draft whose root app has its own Dockerfile (published and signed). */
function keyEnv(): Planned {
  const plain = profileOf([node()], { private: true });
  const prof = profileOf([node({ dockerfile: 'Dockerfile' })], { private: true });
  const plan: SigningPlan = { mode: 'key-env', images: [{ service: 'app', repo: 'ghcr.io/o/r/pipegen-app' }], cosignPubSha256: createHash('sha256').update('a public key', 'utf8').digest('hex') };
  return planned(prof, { caps: KE_CAPS, needs: floorNeeds(plain, KE_CAPS), over: { centralPin: REAL_PIN, signing: plan } });
}

/** The assembled files of each layout (every repo); only the workflows are of interest to the callers. */
export function realAssembled(): Record<'public' | 'private' | 'key-env', CreatedFile[]> {
  const ke = keyEnv();
  const deploy = { 'image-publish': releaseJobs(ke.draft, { platform: p })['image-publish'] as Job };
  return {
    public: lay(planned(profileOf())),
    private: lay(planned(profileOf([node()], { private: true }), { over: { centralPin: REAL_PIN } })),
    'key-env': lay(ke, { mode: 'key-env', deploy }),
  };
}

export const isWorkflowFile = (f: CreatedFile): boolean => f.path.startsWith('.github/workflows/');
