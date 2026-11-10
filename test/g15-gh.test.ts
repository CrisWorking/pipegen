// v0.2 Plan G, sub-task G15a (carries B5-B7; rulings B3 d, P-5, G15-R0 4 and 5): the reviewed pinned gh release entry. Attest mode verifies
// with this binary (installed by its sha256, run by its absolute path), never the runner's gh. The pin data is the controller's (fetched
// 2026-11-06, open question 5): v2.103.3, the newest non-prerelease at least 7 days old, with --source-digest.
import { readFileSync } from 'node:fs';
import { parse, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { COOLDOWN_DAYS } from '../src/engine/pin.js';
import { loadReviewed, MUST_VERIFY, ReviewedListError } from '../src/engine/reviewed.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { egressSetsForTool } from '../src/engine/egress.js';
import { GH_ID } from '../src/engine/signing.js';
import { makeTempDir, writeIn } from './helpers/make-repo.js';

type Obj = Record<string, unknown>;
const raw = (): { pinnedOn: string; tools: Obj[] } => parse(readFileSync('data/reviewed-tools.yml', 'utf8')) as { pinnedOn: string; tools: Obj[] };
const ghRaw = (): Obj => raw().tools.find((t) => t.id === GH_ID) as Obj;
const DAY = 86_400_000;

describe('G15a carries 5-7: the reviewed pinned gh entry', () => {
  it('reviewed: the gh entry is pinned by sha256 from cli/cli, at least 7 days old', () => {
    const gh = loadReviewed().find((t) => t.id === GH_ID);
    expect(gh).toBeDefined();
    const c = gh!.candidate;
    expect(c).toMatchObject({ id: 'gh', repo: 'cli/cli', kind: 'cli', version: 'v2.103.3', source: 'reviewed', reviewed: true });
    expect(c.pin).toEqual({ checksum: '4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d' });
    expect(gh!.step.cli?.install).toEqual({ method: 'github-release', package: 'gh_2.103.3_linux_amd64.tar.gz', version: 'v2.103.3' });
    expect(gh!.step.cli?.command[0]).toBe('gh');
    expect(gh!.reviewedBy).toBe('Claude delegated DECISIONS 105');
    // the release's published_at, and the day it was pinned (the controller's fetch): the cooldown is measured from the entry's own pin day
    const e = ghRaw();
    expect(e.releasedAt).toBe('2026-10-26T19:20:08Z');
    expect(typeof e.pinnedOn).toBe('string');
    expect(Date.parse(e.pinnedOn as string) - Date.parse(e.releasedAt as string)).toBeGreaterThanOrEqual(COOLDOWN_DAYS * DAY);
    // its install reaches only the release download host (the github-releases set); the verify job adds ghcr
    expect(egressSetsForTool(gh!)).toEqual(['github-releases']);
    // its argv policy: the release binary, `gh attestation verify` and nothing else (the verify step adds its own reviewed flags)
    expect(ARGV_POLICIES.gh).toMatchObject({ method: 'github-release', package: 'gh_2.103.3_linux_amd64.tar.gz', exe: 'gh', sub: ['attestation', 'verify'] });
    // the four flags and --source-digest are confirmed in the pinned version's source (the controller's pin data, verify.go:259-268)
    const comment = readFileSync('data/reviewed-tools.yml', 'utf8');
    const block = comment.slice(comment.lastIndexOf('\n\n', comment.indexOf('  - id: gh\n')), comment.indexOf('  - id: gh\n'));
    expect(block).toMatch(/pkg\/cmd\/attestation\/verify\/verify\.go:259-268/);
    for (const f of ['--signer-workflow', '--signer-digest', '--source-ref', '--source-digest', '--deny-self-hosted-runners']) expect(block, f).toContain(f);
  });

  it('reviewed: the gh entry claims no attestation check that was not made; cli/cli joins MUST_VERIFY together with its verifiedWith', () => {
    // G15-R0 4 and 5: the release's build-provenance attestation is not checked yet (the controller checks it live with an independent gh
    // before the tag). Until then the entry records no verifiedWith (a recorded check is a fact, never a plan), and cli/cli is not on
    // MUST_VERIFY (the loader would refuse the whole list without it); both land together after the live check (reviewed.ts is outside
    // the gate bundle, so no new gate tag is needed)
    const gh = loadReviewed().find((t) => t.id === GH_ID);
    expect(MUST_VERIFY.has('cli/cli')).toBe(gh?.verifiedWith !== undefined);
    if (gh?.verifiedWith === undefined) {
      const text = readFileSync('data/reviewed-tools.yml', 'utf8');
      const block = text.slice(text.lastIndexOf('\n\n', text.indexOf('  - id: gh\n')), text.indexOf('  - id: gh\n'));
      expect(block).toMatch(/attestation[^\n]*not checked yet/);
    } else {
      // and once it is there, the entry without it is refused
      const file = raw();
      const e = structuredClone(ghRaw());
      delete e.verifiedWith;
      const dir = makeTempDir();
      writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: file.pinnedOn, tools: [e] }));
      expect(() => loadReviewed(`${dir}/reviewed-tools.yml`)).toThrow(ReviewedListError);
    }
  });

  it('reviewed: the gh entry records its live attestation check (deployment.yml on trunk, the issuer, the source commit) and cli/cli is on MUST_VERIFY', () => {
    // the LIVE line of 2026-11-06: gh attestation verify --repo cli/cli exits 0 for the pinned linux amd64 archive (L/fixtures-G15/v.json)
    const gh = loadReviewed().find((t) => t.id === GH_ID);
    expect(MUST_VERIFY.has('cli/cli')).toBe(true);
    expect(gh?.verifiedWith).toEqual({
      method: 'github-attestation', asset: 'gh_2.103.3_linux_amd64.tar.gz',
      identity: 'https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk',
      issuer: 'https://token.actions.githubusercontent.com', sourceDigest: '63837fb778d6a39f02be0ce76ff89f2bc8d74bdc', verifiedOn: '2026-11-06',
    });
    const file = raw();
    const tryLoad = (patch: (e: Obj) => void): (() => unknown) => {
      const e = structuredClone(ghRaw());
      patch(e);
      const dir = makeTempDir();
      writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: file.pinnedOn, tools: [e] }));
      return () => loadReviewed(`${dir}/reviewed-tools.yml`);
    };
    const vw = (e: Obj): Obj => e.verifiedWith as Obj;
    expect(tryLoad(() => undefined)).not.toThrow();
    // a branch-signed identity is accepted only as the one reviewed signer of this repo, a GitHub attestation of the pinned asset itself,
    // with the source commit recorded: anything else is the tag-only rule's refusal
    expect(tryLoad((e) => { delete vw(e).sourceDigest; })).toThrow(/sourceDigest/);
    expect(tryLoad((e) => { vw(e).sourceDigest = '63837fb'; })).toThrow(ReviewedListError);
    expect(tryLoad((e) => { vw(e).sourceDigest = '63837FB778D6A39F02BE0CE76FF89F2BC8D74BDC'; })).toThrow(ReviewedListError);
    expect(tryLoad((e) => { vw(e).method = 'cosign-bundle'; })).toThrow(/github-attestation/);
    expect(tryLoad((e) => { vw(e).asset = 'gh_2.103.3_checksums.txt'; })).toThrow(/asset/);
    expect(tryLoad((e) => { vw(e).identity = 'https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/main'; })).toThrow(/identity/);
    expect(tryLoad((e) => { vw(e).identity = 'https://github.com/cli/cli/.github/workflows/other.yml@refs/heads/trunk'; })).toThrow(/identity/);
    expect(tryLoad((e) => { vw(e).identity = 'https://github.com/evil/cli/.github/workflows/deployment.yml@refs/heads/trunk'; })).toThrow(/identity/);
    expect(tryLoad((e) => { vw(e).issuer = 'https://example.com'; })).toThrow(ReviewedListError);
    // a recorded source commit on a tag identity claims nothing the tag rule checks: refused, so it never reads as a binding
    const trivy = structuredClone(raw().tools.find((t) => t.id === 'trivy-config') as Obj);
    (trivy.verifiedWith as Obj).sourceDigest = '63837fb778d6a39f02be0ce76ff89f2bc8d74bdc';
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: file.pinnedOn, tools: [trivy] }));
    expect(() => loadReviewed(`${dir}/reviewed-tools.yml`)).toThrow(/sourceDigest/);
    // the trunk identity is cli/cli's alone: another repo's entry may not claim a branch signer
    const tb = structuredClone(raw().tools.find((t) => t.id === 'trivy-config') as Obj);
    Object.assign(tb.verifiedWith as Obj, { method: 'github-attestation', identity: 'https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/heads/main', sourceDigest: '63837fb778d6a39f02be0ce76ff89f2bc8d74bdc' });
    const dir2 = makeTempDir();
    writeIn(dir2, 'reviewed-tools.yml', stringify({ pinnedOn: file.pinnedOn, tools: [tb] }));
    expect(() => loadReviewed(`${dir2}/reviewed-tools.yml`)).toThrow(/identity/);
  });

  it('reviewed: an entry pin day is never before the list\'s, never in the future, and its cooldown, review and check dates count from it', () => {
    const file = raw();
    const gh = structuredClone(ghRaw());
    const tryLoad = (e: Obj): (() => unknown) => {
      const dir = makeTempDir();
      writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: file.pinnedOn, tools: [e] }));
      return () => loadReviewed(`${dir}/reviewed-tools.yml`);
    };
    expect(tryLoad(gh)).not.toThrow();
    // without its own pin day the release is younger than the cooldown before the list's pinnedOn
    const noDay = structuredClone(gh); delete noDay.pinnedOn;
    expect(tryLoad(noDay)).toThrow(/cooldown/);
    expect(tryLoad({ ...structuredClone(gh), pinnedOn: '2026-10-01T00:00:00Z' })).toThrow(/pinnedOn is before the list's/);
    // the day before the list's: refused for that reason alone (the release is older than both days)
    expect(tryLoad({ ...structuredClone(gh), releasedAt: '2026-10-01T00:00:00Z', pinnedOn: '2026-10-27T00:00:00Z' })).toThrow(/pinnedOn is before the list's/);
    expect(tryLoad({ ...structuredClone(gh), pinnedOn: '2999-01-01T00:00:00Z' })).toThrow(/future/);
    expect(tryLoad({ ...structuredClone(gh), pinnedOn: '2026-10-30T00:00:00Z' })).toThrow(/cooldown/);
    expect(tryLoad({ ...structuredClone(gh), reviewedAt: '2026-11-01' })).toThrow(/reviewedAt is before/);
  });
});

describe('G15a carry 8: attest verify binds the deployed commit', () => {
  it('render: attest verify binds --source-digest to the deployed commit (the push\'s GITHUB_SHA, checked first; a workflow_run deploy gets no verify job)', async () => {
    const { renderVerifySteps } = await import('../src/engine/signing.js');
    const { planned, profileOf, node } = await import('./helpers/assemble.js');
    const gh = loadReviewed().find((t) => t.id === GH_ID)!;
    const img = { service: 'app', repo: 'ghcr.io/o/r/pipegen-app' };
    const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })], { private: true });
    const draft = planned(prof, { over: { centralPin: { repo: 'o/pipelines', sha: 'c'.repeat(40) }, signing: { mode: 'attest', images: [img] } } }).draft;
    const run = String(renderVerifySteps(gh, draft, img)[1]?.run);
    const lines = run.split('\n');
    const check = lines.findIndex((l) => l.includes('GITHUB_SHA:-') && l.includes('{40}'));
    const verify = lines.findIndex((l) => l.includes(' attestation verify '));
    expect(check).toBeGreaterThan(-1);
    expect(verify).toBeGreaterThan(check);
    const v = lines[verify] as string;
    // every binding flag of the attest verify, each once: the source repo, its ref, its commit, the signer workflow at its commit, hosted only
    for (const f of ['--repo', '--source-ref', '--source-digest', '--signer-workflow', '--signer-digest', '--deny-self-hosted-runners']) expect(v.split(` ${f} `).length + (v.endsWith(` ${f}`) ? 1 : 0) - 1, f).toBe(1);
    expect(v).toContain('--source-digest "$GITHUB_SHA"');
    // G15a-R7 spec 5: the verify job is only ever a push deploy's, so GITHUB_SHA is the deployed commit: planned on the attest pipeline, a push
    // deploy gets the verify job inserted (with this line), a workflow_run deploy gets none and is listed as a gap
    const { assemble } = await import('../src/layers/assemble.js');
    const { planVerifyInserts, releaseJobs } = await import('../src/layers/deploy.js');
    const { REVIEWED } = await import('./helpers/debate-fixtures.js');
    const { p } = await import('./helpers/assemble.js');
    const path = '.github/workflows/deploy.yml';
    const used = ['sec', 'retsUsed'].join('');
    const push = ['on:', '  push:', '    branches: [main]', 'jobs:', '  deploy:', '    runs-on: ubuntu-latest', '    environment: production', '    steps:', '      - run: ./ship.sh', ''].join('\n');
    const wr = push.replace('  push:\n    branches: [main]', '  workflow_run:\n    workflows: [ci]\n    types: [completed]');
    const caps = { branchProtection: true, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: false };
    const plan = (text: string, trigger: string) => {
      const prof2 = profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })], { private: true, existingWorkflows: [{ path, triggers: [trigger], deploys: true, [used]: [], jobs: [] } as never] });
      const x = planned(prof2, { caps, over: { centralPin: { repo: 'o/pipelines', sha: 'c'.repeat(40) }, signing: { mode: 'attest', images: [img] } } });
      const a = assemble(x.draft, { gate: REVIEWED.find((t) => t.id === 'pipegen-gate')!, reviewed: REVIEWED, platform: p, mode: 'attest', layout: 'central', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) });
      return planVerifyInserts(a.draft, new Map([[path, text]]), a.verify);
    };
    const onPush = plan(push, 'push');
    expect(onPush.gaps).toEqual([]);
    expect(onPush.inserts).toHaveLength(1);
    expect(onPush.inserts[0]?.file.content).toContain('--source-digest "$GITHUB_SHA"');
    const onRun = plan(wr, 'workflow_run');
    expect(onRun.inserts).toEqual([]);
    expect(onRun.gaps).toEqual([{ path, triggers: ['workflow_run'], why: expect.stringMatching(/workflow_run/) }]);
  });
});
