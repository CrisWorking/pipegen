// v0.2 Plan G, sub-task G15a (carries A1-A4; release blocker): the reviewed Sigstore egress set, mode-scoped to the keyless verify job.
// Keyless verify reads Sigstore's TUF root and its transparency log; without those hosts behind the egress block it always fails closed.
// The set reaches only that job: never cosign's tool-wide sets (the proof harness and the key-env sign job read them), never a job that
// holds a user secret (rekor.sigstore.dev accepts anyone's entries), and the keyless sign job keeps its documented no-block exception.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { EGRESS_DOMAIN_SETS, KEYLESS_VERIFY_SETS, SHARED_CDN_SETS, egressSetsForTool, renderEgressStep } from '../src/engine/egress.js';
import { SIGSTORE_SET } from '../src/engine/egress-sets.js';
import { assemble, judgeAssembled, type AssembledFiles } from '../src/layers/assemble.js';
import { planVerifyInserts, releaseJobs, type VerifyPlan } from '../src/layers/deploy.js';
import type { Job } from '../src/layers/jobs.js';
import { signJob } from '../src/layers/central.js';
import type { Capabilities, CreatedFile, ExistingWorkflow, PipelineDraft, ReviewedTool, Service, SigningPlan } from '../src/types.js';
import { cosignPub } from './helpers/cosign-keys.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const COSIGN = REVIEWED.find((t) => t.id === 'cosign') as ReviewedTool;
const KE_CAPS: Capabilities = { ...CAPS, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true };
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const PUB_SHA = createHash('sha256').update(cosignPub(3), 'utf8').digest('hex');
const IMG = { service: 'app', repo: 'ghcr.io/o/r-app' };
const SERVER: Service = node({ dockerfile: 'Dockerfile', port: 3000 });
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Omit<Parameters<typeof judgeAssembled>[1], 'extra'>;
const SIGSTORE_HOSTS = ['rekor.sigstore.dev', 'tuf-repo-cdn.sigstore.dev'];

/** A user deploy workflow (push to main), so the verify job is inserted there (deploy.ts). */
const DEPLOY = ['on:', '  push:', '    branches: [main]', 'jobs:', '  deploy:', '    runs-on: ubuntu-latest', '    environment: production', '    steps:', '      - run: ./ship.sh', ''].join('\n');
const WF = '.github/workflows/deploy.yml';
const USED = ['sec', 'retsUsed'].join('');
const wfOf = (path: string): ExistingWorkflow => ({ path, triggers: ['push'], deploys: true, [USED]: [], jobs: [] }) as unknown as ExistingWorkflow;

type Kind = 'keyless' | 'key-env';
function world(kind: Kind): { draft: PipelineDraft; a: AssembledFiles; v: VerifyPlan } {
  const priv = kind !== 'keyless';
  const prof = profileOf([SERVER], { private: priv, existingWorkflows: [wfOf(WF)] });
  const caps = kind === 'key-env' ? KE_CAPS : CAPS;
  const signing: SigningPlan = kind === 'keyless' ? { mode: 'keyless', images: [IMG] } : { mode: 'key-env', images: [IMG], cosignPubSha256: PUB_SHA };
  const x = planned(prof, { caps, over: { ...(priv ? { centralPin: PIN } : {}), signing } });
  const a = assemble(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode: kind, layout: priv ? 'central' : 'local', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) });
  return { draft: x.draft, a, v: planVerifyInserts(a.draft, new Map([[WF, DEPLOY]]), a.verify) };
}
const judge = (w: { a: AssembledFiles; v: VerifyPlan }, extra: CreatedFile[] = w.v.inserts.map((i) => i.file)) => judgeAssembled(w.a, { ...JD, extra });
const hostsOf = (j: Job | Obj): string[] => {
  const h = ((j.steps ?? []) as Obj[]).find((s) => typeof s.uses === 'string' && /bullfrog/.test(s.uses as string));
  return h === undefined ? [] : String((h.with as Obj)['allowed-domains']).split('\n');
};
const allFiles = (w: { a: AssembledFiles; v: VerifyPlan }): CreatedFile[] => [...w.a.files, ...w.v.inserts.map((i) => i.file)];
/** Every job of every assembled workflow file, by `<path>#<id>`. */
const jobsOf = (w: { a: AssembledFiles; v: VerifyPlan }): Map<string, Obj> => {
  const out = new Map<string, Obj>();
  for (const f of allFiles(w)) {
    if (!f.path.startsWith('.github/workflows/')) continue;
    const js = (parse(f.content) as Obj).jobs as Obj | undefined;
    for (const [id, j] of Object.entries(js ?? {})) out.set(`${f.path}#${id}`, j as Obj);
  }
  return out;
};

describe('G15a carry 1: the reviewed Sigstore set', () => {
  it('egress: the sigstore set holds exact hosts only, each with its source', () => {
    const set = EGRESS_DOMAIN_SETS[SIGSTORE_SET];
    expect([...set].sort()).toEqual(SIGSTORE_HOSTS);
    for (const h of set) {
      expect(h).toMatch(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/);
      expect(h).not.toMatch(/[*:/]|\.$/);
    }
    // no signing host: no job pipegen gives this set signs (fulcio is the sign side; the keyless sign job keeps its no-block exception)
    expect(set).not.toContain('fulcio.sigstore.dev');
    // each host's source is written next to the set, with the pinned cosign's file and line, and marked for the live checklist
    const src = readFileSync('src/engine/egress-sets.ts', 'utf8');
    const block = src.slice(src.indexOf('- sigstore:'), src.indexOf('*/', src.indexOf('- sigstore:')));
    for (const h of SIGSTORE_HOSTS) expect(block, h).toContain(h);
    expect(block).toMatch(/cosign v3\.1\.3/);
    expect(block).toMatch(/cmd\/cosign\/cli\/verify\/common\.go:191/);
    expect(block).toMatch(/cmd\/cosign\/cli\/verify\/common\.go:134/);
    expect(block).toMatch(/sigstore-go v1\.2\.2 pkg\/tuf\/options\.go:142/);
    expect(block).toMatch(/the live checklist verifies/);
    // the reviewed bullfrog entry offers it as a choice (the bundled allowed-domains rule only accepts offered labels)
    const bullfrog = REVIEWED.find((t) => t.id === 'bullfrog') as ReviewedTool;
    expect(bullfrog.choices['allowed-domains']).toContain(SIGSTORE_SET);
    expect(renderEgressStep([SIGSTORE_SET], { dockerNetworks: false }).with?.['allowed-domains']).toContain('rekor.sigstore.dev');
  });
});

describe('G15a carries 2-3: only the keyless verify job reaches Sigstore', () => {
  it('assemble: keyless verify reaches the Sigstore hosts and gets no release-blocker note', async () => {
    const w = world('keyless');
    expect(KEYLESS_VERIFY_SETS).toEqual([SIGSTORE_SET]);
    const hosts = hostsOf(w.a.verify as Job);
    for (const h of SIGSTORE_HOSTS) expect(hosts, h).toContain(h);
    expect(w.a.notes.join('\n')).not.toMatch(/Your deploys stop for now/);
    expect(w.a.notes.join('\n')).not.toMatch(/before release/);
    expect(w.v.inserts.length).toBe(1);
    for (const h of SIGSTORE_HOSTS) expect(w.v.inserts[0]?.text, h).toContain(h);
    expect(shown(await judge(w))).toBe('');
  });

  it('egress: the sigstore set never reaches the key-env sign job, the proof harness or a job holding a user secret', async () => {
    // the tool-wide sets of cosign (they feed the proof harness and the key-env sign job) hold no Sigstore set
    expect(egressSetsForTool(COSIGN)).not.toContain(SIGSTORE_SET);
    // E3-R3: anyone can write to the transparency log, so the set counts as shared: never in a job with a user secret
    expect(SHARED_CDN_SETS.has(SIGSTORE_SET)).toBe(true);
    const ke = world('key-env');
    const sign = signJob(ke.draft, 'key-env', { reviewed: REVIEWED, platform: p });
    for (const h of SIGSTORE_HOSTS) expect(hostsOf(sign as unknown as Obj), h).not.toContain(h);
    // the key-env verify job does not get it either (it checks with the recorded key and --insecure-ignore-tlog)
    for (const h of SIGSTORE_HOSTS) expect(hostsOf(ke.a.verify as Job), h).not.toContain(h);
    // no other job of either world holds a Sigstore host
    for (const w of [world('keyless'), ke]) {
      for (const [where, j] of jobsOf(w)) {
        if (where.endsWith('#pipegen-verify') && w.draft.signing?.mode === 'keyless') continue;
        for (const h of SIGSTORE_HOSTS) expect(hostsOf(j), `${where} ${h}`).not.toContain(h);
      }
    }
    // the harness's cosign job reads egressSetsForTool(cosign) (src/proof/harness.ts): no Sigstore host there either
    expect(readFileSync('src/proof/harness.ts', 'utf8')).not.toMatch(/sigstore\.dev|KEYLESS_VERIFY_SETS|SIGSTORE_SET/);
  });

  it('referee: a keyless verify job without its egress step → refused', async () => {
    const w = world('keyless');
    const ins = w.v.inserts[0]?.file as CreatedFile;
    expect(ins).toBeDefined();
    const doc = parse(ins.content) as Obj;
    const vj = (doc.jobs as Obj)['pipegen-verify'] as Obj;
    const steps = vj.steps as Obj[];
    expect(String(steps[0]?.uses)).toMatch(/bullfrog/);
    const without = renderEgressStep(['ghcr', 'github-releases'], { dockerNetworks: false }) as unknown as Obj;
    for (const changed of [steps.slice(1), [without, ...steps.slice(1)]]) {
      const d2 = structuredClone(doc);
      ((d2.jobs as Obj)['pipegen-verify'] as Obj).steps = changed;
      const out = shown(await judge(w, [{ ...ins, content: JSON.stringify(d2) }]));
      expect(out).toMatch(/pipegen-verify[\s\S]*(egress step|Sigstore)/);
    }
  });

  it('referee: a Sigstore host in any job but the keyless verify job → refused', async () => {
    const w = world('key-env');
    const f = w.a.files.find((x) => /--sign\.yml$/.test(x.path)) as CreatedFile;
    const doc = parse(f.content) as Obj;
    const job = (doc.jobs as Obj).sign as Obj;
    const steps = job.steps as Obj[];
    steps[0] = renderEgressStep(['ghcr', 'github-releases', SIGSTORE_SET], { dockerNetworks: false }) as unknown as Obj;
    const files = w.a.files.map((x) => (x === f ? { ...f, content: JSON.stringify(doc) } : x));
    expect(shown(await judgeAssembled({ ...w.a, files }, { ...JD, extra: w.v.inserts.map((i) => i.file) }))).toMatch(/Sigstore/);
    // the key-env verify job (same job id as the keyless one) may not open them either: the mode is the repository's, not the job's name
    const ins = w.v.inserts[0]?.file as CreatedFile;
    const vdoc = parse(ins.content) as Obj;
    const vj = (vdoc.jobs as Obj)['pipegen-verify'] as Obj;
    const vsteps = vj.steps as Obj[];
    expect(String(vsteps[0]?.uses)).toMatch(/bullfrog/);
    const had = String(((vsteps[0] as Obj).with as Obj)['allowed-domains']).split('\n');
    const sets = ['ghcr', 'github-releases', SIGSTORE_SET].filter((x) => x !== SIGSTORE_SET || !had.includes('rekor.sigstore.dev'));
    vsteps[0] = renderEgressStep(sets as never, { dockerNetworks: false }) as unknown as Obj;
    expect(shown(await judge(w, [{ ...ins, content: JSON.stringify(vdoc) }]))).toMatch(/pipegen-verify[\s\S]*Sigstore/);
  });
});
