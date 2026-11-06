// v0.2 Plan G, sub-task G15a (ruling G15a-R0b item 2): attest verify switched on. gh's own hosts (its source at v2.103.3, and the bundle host
// observed on the attestations API) form the reviewed set ATTEST_VERIFY_SETS, which only the attest verify job gets; gh runs with
// --no-public-good, since attest mode is only ever a private repository's (its attestations are signed by GitHub's own instance).
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { ATTEST_VERIFY_SETS, EGRESS_DOMAIN_SETS, SHARED_CDN_SETS, renderEgressStep } from '../src/engine/egress.js';
import { GITHUB_ATTEST_SET } from '../src/engine/egress-sets.js';
import { allowedDomainsProblem } from '../src/engine/tool-flags.js';
import { assemble, judgeAssembled, type AssembledFiles } from '../src/layers/assemble.js';
import { planVerifyInserts, releaseJobs, type VerifyPlan } from '../src/layers/deploy.js';
import { renderVerifySteps, GH_ID } from '../src/engine/signing.js';
import type { Job } from '../src/layers/jobs.js';
import type { Capabilities, CreatedFile, ExistingWorkflow, PipelineDraft, ReviewedTool, Service } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { loadReviewed } from '../src/engine/reviewed.js';

const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const AT_CAPS: Capabilities = { ...CAPS, attestations: true, environments: true };
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const IMG = { service: 'app', repo: 'ghcr.io/o/r-app' };
const SERVER: Service = node({ dockerfile: 'Dockerfile', port: 3000 });
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Omit<Parameters<typeof judgeAssembled>[1], 'extra'>;
const HOSTS = ['tmaproduction.blob.core.windows.net', 'tuf-repo.github.com'];
const DEPLOY = ['on:', '  push:', '    branches: [main]', 'jobs:', '  deploy:', '    runs-on: ubuntu-latest', '    environment: production', '    steps:', '      - run: ./ship.sh', ''].join('\n');
const WF = '.github/workflows/deploy.yml';
const USED = ['sec', 'retsUsed'].join('');
const wfOf = (path: string): ExistingWorkflow => ({ path, triggers: ['push'], deploys: true, [USED]: [], jobs: [] }) as unknown as ExistingWorkflow;

function world(): { draft: PipelineDraft; a: AssembledFiles; v: VerifyPlan } {
  const prof = profileOf([SERVER], { private: true, existingWorkflows: [wfOf(WF)] });
  const x = planned(prof, { caps: AT_CAPS, over: { centralPin: PIN, signing: { mode: 'attest', images: [IMG] } } });
  const a = assemble(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode: 'attest', layout: 'central', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) });
  return { draft: x.draft, a, v: planVerifyInserts(a.draft, new Map([[WF, DEPLOY]]), a.verify) };
}
const judge = (w: { a: AssembledFiles; v: VerifyPlan }, extra: CreatedFile[] = w.v.inserts.map((i) => i.file)) => judgeAssembled(w.a, { ...JD, extra });
const hostsOf = (j: Job | Obj): string[] => {
  const h = ((j.steps ?? []) as Obj[]).find((s) => typeof s.uses === 'string' && /bullfrog/.test(s.uses as string));
  return h === undefined ? [] : String((h.with as Obj)['allowed-domains']).split('\n');
};
/** The inserted verify job, parsed, with a function that judges it after an edit. */
function insertedVerify(w: ReturnType<typeof world>): { steps: Obj[]; judgeWith: (steps: Obj[]) => Promise<string> } {
  const ins = w.v.inserts[0]?.file as CreatedFile;
  const doc = parse(ins.content) as Obj;
  const steps = (((doc.jobs as Obj)['pipegen-verify'] as Obj).steps as Obj[]);
  return {
    steps,
    judgeWith: async (changed) => {
      const d2 = structuredClone(doc);
      ((d2.jobs as Obj)['pipegen-verify'] as Obj).steps = changed;
      return shown(await judge(w, [{ ...ins, content: JSON.stringify(d2) }]));
    },
  };
}

describe('G15a-R0b item 2: attest verify on, with gh\'s reviewed hosts', () => {
  it('egress: the GitHub attestation set holds exact hosts only, each with its source', () => {
    expect([...EGRESS_DOMAIN_SETS[GITHUB_ATTEST_SET]].sort()).toEqual(HOSTS);
    for (const h of EGRESS_DOMAIN_SETS[GITHUB_ATTEST_SET]) expect(h).not.toMatch(/[*:/]|\.$/);
    expect(ATTEST_VERIFY_SETS).toEqual([GITHUB_ATTEST_SET]);
    // the blob host serves anyone's content: a shared set, never in a job with a user secret
    expect(SHARED_CDN_SETS.has(GITHUB_ATTEST_SET)).toBe(true);
    const src = readFileSync('src/engine/egress-sets.ts', 'utf8');
    const block = src.slice(src.indexOf('- github-attest:'), src.indexOf('*/', src.indexOf('- github-attest:')));
    for (const h of HOSTS) expect(block, h).toContain(h);
    for (const cite of ['gh v2.103.3', 'pkg/cmd/attestation/verification/tuf.go:19', 'pkg/cmd/attestation/verification/sigstore.go:340', 'pkg/cmd/attestation/api/client.go:201-215',
      'observed live 2026-11-06 on the attestations API', 'sigstore.go:78', 'the live checklist verifies']) expect(block, cite).toContain(cite);
    // the bullfrog entry offers it, and a wildcard in its place is refused by the allowed-domains rule
    const bullfrog = loadReviewed().find((t) => t.id === 'bullfrog') as ReviewedTool;
    expect(bullfrog.choices['allowed-domains']).toContain(GITHUB_ATTEST_SET);
    const domains = (s: string[]): string => s.join('\n');
    const ok = String(renderEgressStep(['github-core', 'ghcr', 'github-releases', GITHUB_ATTEST_SET], { dockerNetworks: false }).with?.['allowed-domains']);
    expect(allowedDomainsProblem(ok, bullfrog.choices['allowed-domains'] as string[])).toBeNull();
    expect(allowedDomainsProblem(domains(ok.split('\n').map((h) => (h === 'tmaproduction.blob.core.windows.net' ? '*.blob.core.windows.net' : h))), bullfrog.choices['allowed-domains'] as string[])).not.toBeNull();
  });

  it('render: attest verify runs gh with --no-public-good (private repositories only)', () => {
    const gh = loadReviewed().find((t) => t.id === GH_ID) as ReviewedTool;
    const w = world();
    const line = String(renderVerifySteps(gh, w.draft, IMG)[1]?.run).split('\n').find((l) => l.includes(' attestation verify ')) as string;
    expect(line).toContain(' --no-public-good');
    // sigstore.go:78: with --no-public-good gh skips the public-good verifier (and its TUF host); attest mode is only a private repository's
    const pub = { ...w.draft, profile: { ...w.draft.profile, private: false } };
    expect(() => renderVerifySteps(gh, pub, IMG)).toThrow(/private/);
  });

  it('assemble: the attest verify job reaches exactly gh\'s hosts and passes the referee', async () => {
    const w = world();
    const hosts = hostsOf(w.a.verify as Job);
    for (const h of HOSTS) expect(hosts, h).toContain(h);
    expect(hosts).not.toContain('tuf-repo-cdn.sigstore.dev');
    expect(hosts).not.toContain('rekor.sigstore.dev');
    expect(w.v.inserts.length).toBe(1);
    expect(shown(await judge(w))).toBe('');
  });

  it('referee: an attest verify job whose egress step misses gh\'s hosts, or holds a wildcard bundle host → refused', async () => {
    const w = world();
    const { steps, judgeWith } = insertedVerify(w);
    expect(String(steps[0]?.uses)).toMatch(/bullfrog/);
    // without the egress step, or with one that misses the set
    expect(await judgeWith(steps.slice(1))).toMatch(/pipegen-verify/);
    const without = renderEgressStep(['github-core', 'ghcr', 'github-releases'], { dockerNetworks: false }) as unknown as Obj;
    expect(await judgeWith([without, ...steps.slice(1)])).toMatch(/pipegen-verify[\s\S]*tuf-repo\.github\.com/);
    // the bundle host as a wildcard (any Azure blob account) is refused
    const wild = structuredClone(steps[0]) as Obj;
    (wild.with as Obj)['allowed-domains'] = String((wild.with as Obj)['allowed-domains']).replace('tmaproduction.blob.core.windows.net', '*.blob.core.windows.net');
    expect(await judgeWith([wild, ...steps.slice(1)])).not.toBe('');
  });

  it('referee: gh\'s attestation hosts in any job but the attest verify job → refused', async () => {
    const w = world();
    const f = w.a.files.find((x) => /pipegen\.yml$/.test(x.path) || /--merge\.yml$/.test(x.path)) as CreatedFile;
    const doc = parse(f.content) as Obj;
    const [id, job] = Object.entries(doc.jobs as Obj).find(([, j]) => Array.isArray((j as Obj).steps) && /bullfrog/.test(String(((j as Obj).steps as Obj[])[0]?.uses))) as [string, Obj];
    const steps = job.steps as Obj[];
    const was = String((steps[0]?.with as Obj)['allowed-domains']).split('\n');
    (steps[0]?.with as Obj)['allowed-domains'] = [...was, ...HOSTS].join('\n');
    const files = w.a.files.map((x) => (x === f ? { ...f, content: JSON.stringify(doc) } : x));
    expect(shown(await judgeAssembled({ ...w.a, files }, { ...JD, extra: w.v.inserts.map((i) => i.file) })), id).toMatch(/attestation/);
  });
});
