// v0.2 Plan G, sub-task G15a (carries C10-C12; rulings G3-R1, G3-R2, G5-R1-b): attest-mode signing. The sign job is the project's central
// sign workflow (private repositories only): the digest hand-off of each image (image-publish's artifact), pipegen's digest step (the file
// read, checked as sha256:<64 hex>, the registry login for the push, the digest as the step's output), and the reviewed actions/attest v4
// with that output as its subject-digest (never a literal) and push-to-registry true. Nothing else runs in the job.
import { readFileSync } from 'node:fs';
import { Document, parse, parseDocument, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { attestDigestStepId, DEPLOY_PUSH_IF } from '../src/engine/job-rules.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { RenderError } from '../src/engine/render-error.js';
import { renderPlatformStep } from '../src/engine/render-step.js';
import { imageDigestArtifact, renderAttestDigestStep } from '../src/engine/signing.js';
import { rendererInputProblems } from '../src/engine/tool-flags.js';
import { sharedWorkflows, signCallerJob, signJob, signPermissions, SIGN_JOB_ID } from '../src/layers/central.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool } from '../src/types.js';
import { draftOf, imageProf, jobsOf, p, workflow } from './helpers/gate-pipeline.js';
import { reviewedList } from './helpers/render.js';
import { makeTempDir, writeIn } from './helpers/make-repo.js';
import { loadReviewed } from '../src/engine/reviewed.js';

type Obj = Record<string, any>;
const OIDC = ['id', 'token'].join('-');
const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
const deps = { reviewed: reviewedList(), platform: p };
const SHA = 'a'.repeat(40);
const IMG = { service: 'app', repo: 'ghcr.io/o/r/pipegen-app' };
const NEEDS = ['gate', 'image-publish'];
const CAPS_BASE: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: false };
const ATTEST_CAPS: Capabilities = { ...CAPS_BASE, attestations: true, environments: true };
const DEPLOY_ON = { push: { branches: ['main'] }, pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
const at = (over: Partial<PipelineDraft> = {}): PipelineDraft =>
  draftOf({ profile: { ...imageProf, private: true }, capabilities: ATTEST_CAPS, centralPin: { repo: 'o/pipelines', sha: SHA }, signing: { mode: 'attest', images: [IMG] }, ...over });
const judge = (files: CreatedFile[], d: PipelineDraft, reviewed: ReviewedTool[] = reviewedList()) =>
  referee(files, d, p, reviewed, LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: { issues: { check: string; message: string }[] }): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
function appCaller(d: PipelineDraft, caller: Record<string, unknown>): CreatedFile {
  const base = workflow(jobsOf(d), { on: DEPLOY_ON });
  const doc = parseDocument(base.content);
  doc.setIn(['jobs', SIGN_JOB_ID], doc.createNode(caller));
  return { ...base, content: doc.toString({ lineWidth: 0 }) };
}
function editSign(f: CreatedFile, edit: (j: Obj) => void): CreatedFile {
  const js = parse(f.content) as Obj;
  edit(js.jobs[SIGN_JOB_ID]);
  const doc = new Document();
  doc.contents = doc.createNode(js);
  return { ...f, content: doc.toString({ lineWidth: 0 }) };
}
const attestSet = (d: PipelineDraft = at()): CreatedFile[] => {
  const shared = sharedWorkflows(d, 'attest', deps);
  expect(shared).toHaveLength(1);
  return [shared[0] as CreatedFile, appCaller(d, signCallerJob(d, 'attest', NEEDS) as Record<string, unknown>)];
};
const digestRef = (repo: string): string => `\${{ steps.${attestDigestStepId(repo)}.outputs.digest }}`;

describe('G15a carries 10-12: the attest sign job', () => {
  it('central: the attest sign job (download, digest step, actions/attest with its output), its file and caller pass the referee', async () => {
    const d = at();
    const j = signJob(d, 'attest', deps);
    // the permissions: attestations write (this mode only), the OIDC token actions/attest signs with, the registry write of push-to-registry
    expect(j.permissions).toEqual({ contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' });
    expect(signPermissions('attest')).toEqual(j.permissions);
    // no environment, no key, no egress step (the per-run OIDC token host can not be listed exactly: threat model T52)
    expect(j.environment).toBeUndefined();
    const steps = j.steps as Obj[];
    expect(steps.map((s) => String(s.uses ?? s.id).replace(/@.*/, ''))).toEqual(['actions/download-artifact', attestDigestStepId(IMG.repo), 'actions/attest']);
    expect(steps[0]?.with).toEqual({ name: imageDigestArtifact('app'), path: `\${{ runner.temp }}/pipegen-out/${imageDigestArtifact('app')}` });
    // the digest step is pipegen's own render: the hand-off file, DIGEST_RE, the step output
    expect(steps[1]).toEqual(renderAttestDigestStep(IMG));
    const run = String(steps[1]?.run);
    expect(run).toContain(`"$RUNNER_TEMP/pipegen-out/${imageDigestArtifact('app')}/digest"`);
    expect(run).toMatch(/\^sha256:\[0-9a-f\]\{64\}\$/);
    expect(run).toContain('echo "digest=$digest" >> "$GITHUB_OUTPUT"');
    // actions/attest v4 at its reviewed pin, the run-time digest form, push-to-registry true
    expect(steps[2]?.uses).toBe(p.attest.step.action?.uses);
    expect(String(steps[2]?.uses)).toMatch(/^actions\/attest@[0-9a-f]{40}$/);
    expect(p.attest.candidate.version.startsWith('v4.')).toBe(true);
    expect(steps[2]?.with).toEqual({ 'push-to-registry': 'true', 'subject-name': IMG.repo, 'subject-digest': digestRef(IMG.repo) });
    // the central file, its caller, and the referee: the whole set passes
    const set = attestSet(d);
    expect(parse(set[0]?.content as string).jobs[SIGN_JOB_ID].permissions).toEqual(j.permissions);
    expect((signCallerJob(d, 'attest', NEEDS) as Obj).permissions).toEqual(j.permissions);
    expect(show(await judge(set, d))).toBe('');
    // another attest action, or another major, is still refused
    const old = { ...p, attest: { ...p.attest, candidate: { ...p.attest.candidate, version: 'v3.0.0' } } } as typeof p;
    expect(() => signJob(d, 'attest', { ...deps, platform: old })).toThrow(/written for actions\/attest v4/);
    // an image off ghcr.io is refused (the registry login is to ghcr.io only)
    expect(() => signJob(at({ signing: { mode: 'attest', images: [{ service: 'app', repo: 'docker.io/o/app' }] } }), 'attest', deps)).toThrow(/ghcr\.io/);
  });

  it('referee: an attest subject-digest from anything but the hand-off file → refused', async () => {
    const d = at();
    const [file, caller] = attestSet(d) as [CreatedFile, CreatedFile];
    // the input table: the run-time form of the digest step of the same image, never a literal or another step's output
    expect(rendererInputProblems('actions/attest', { 'subject-name': IMG.repo, 'subject-digest': digestRef(IMG.repo) })).toEqual([]);
    for (const bad of [`sha256:${'b'.repeat(64)}`, '${{ steps.other.outputs.digest }}', '${{ steps.pipegen-digest.outputs.digest }}', digestRef('ghcr.io/o/r/pipegen-web'), '${{ env.DIGEST }}']) {
      expect(rendererInputProblems('actions/attest', { 'subject-name': IMG.repo, 'subject-digest': bad }).length, bad).toBeGreaterThan(0);
      expect(() => renderPlatformStep('attest', p, { 'subject-name': IMG.repo, 'subject-digest': bad }), bad).toThrow(RenderError);
    }
    const refused = async (edit: (j: Obj) => void, why: string): Promise<void> => {
      const r = await judge([editSign(file, edit), caller], d);
      expect(r.ok, `${why}: ${show(r)}`).toBe(false);
    };
    // a literal digest in the attest step
    await refused((j) => { j.steps[2].with['subject-digest'] = `sha256:${'b'.repeat(64)}`; }, 'literal');
    // the digest step changed (no DIGEST_RE check), so it is not pipegen's step and its output is not the hand-off's
    await refused((j) => { j.steps[1].run = String(j.steps[1].run).replace(/if ! \[\[ "\$digest" =~[^\n]*\n/, ''); }, 'no DIGEST_RE');
    // the digest step reads another file
    await refused((j) => { j.steps[1].run = String(j.steps[1].run).replace('/digest"', '/other"'); }, 'other file');
    // the attest step before its digest step
    await refused((j) => { j.steps = [j.steps[0], j.steps[2], j.steps[1]]; }, 'order');
    // the digest step gone (a step id that is not in the job)
    await refused((j) => { j.steps = [j.steps[0], j.steps[2]]; }, 'missing digest step');
    // another image name than the plan's
    await refused((j) => { j.steps[2].with['subject-name'] = 'ghcr.io/o/r/pipegen-other'; }, 'other image');
    // the attestation kept out of the registry, or push-to-registry left to its default
    await refused((j) => { j.steps[2].with['push-to-registry'] = 'false'; }, 'push-to-registry false');
    await refused((j) => { delete j.steps[2].with['push-to-registry']; }, 'push-to-registry missing');
    // and the reviewed entry can not drop it or set it false (the loader's input policy)
    const file0 = parse(readFileSync('data/reviewed-tools.yml', 'utf8')) as { pinnedOn: string; tools: Obj[] };
    const entry0 = file0.tools.find((t) => t.id === 'actions-attest') as Obj;
    for (const v of [undefined, 'false']) {
      const e = structuredClone(entry0);
      for (const w of [e.step.action.with, e.fixedInputs.with]) { if (v === undefined) delete w['push-to-registry']; else w['push-to-registry'] = v; }
      const dir = makeTempDir();
      writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: file0.pinnedOn, tools: [e] }));
      expect(() => loadReviewed(`${dir}/reviewed-tools.yml`), String(v)).toThrow(/push-to-registry/);
    }
  });

  it('referee: the attest sign job holds only the attest step and the digest step', async () => {
    const d = at();
    const [file, caller] = attestSet(d) as [CreatedFile, CreatedFile];
    const login = renderPlatformStep('docker-login', p, Object.fromEntries([['username', '${{ github.actor }}'], [['pass', 'word'].join(''), ['${{ sec', 'rets.GITHUB_TOKEN }}'].join('')]]), { registry: 'ghcr.io' });
    const checkout = renderPlatformStep('checkout', p);
    const extra: [string, Obj][] = [
      ['a registry login action', login as Obj],
      ['a checkout', checkout as Obj],
      ['a run step', { name: 'x', run: 'echo hi', shell: 'bash' }],
      ['a third-party action', { uses: 'evil/action@' + 'b'.repeat(40) }],
    ];
    for (const [why, step] of extra) {
      const { usesComment: _c, ...plain } = step;
      for (const at2 of [0, 2]) {
        const r = await judge([editSign(file, (j) => { j.steps.splice(at2, 0, plain); }), caller], d);
        expect(r.ok, `${why} at ${at2}: ${show(r)}`).toBe(false);
      }
    }
    // the OIDC token and attestations write only with the attest step (an attest job without it asks for what nothing uses)
    const r = await judge([editSign(file, (j) => { j.steps = j.steps.slice(0, 2); }), caller], d);
    expect(r.issues.some((i) => i.check === 'permissions' && new RegExp(`${OIDC}: write`).test(i.message)), show(r)).toBe(true);
  });

  it('referee: attest-mode image publishing needs the attest sign job', async () => {
    const d = at();
    const publish = { 'runs-on': 'ubuntu-24.04', 'timeout-minutes': 30, permissions: { contents: 'read', packages: 'write' }, 'cache-mode': 'none', if: DEPLOY_PUSH_IF, needs: ['gate'],
      steps: [renderPlatformStep('build-push', p, { file: 'Dockerfile', tags: 'ghcr.io/o/r/pipegen-app:pipegen' }, { push: 'true' })] };
    const base = appCaller(d, signCallerJob(d, 'attest', NEEDS) as Record<string, unknown>);
    const withPublish = (f: CreatedFile): CreatedFile => {
      const doc = parseDocument(f.content);
      doc.setIn(['jobs', 'image-publish'], doc.createNode(publish));
      return { ...f, content: doc.toString({ lineWidth: 0 }) };
    };
    const unsigned = withPublish(workflow(jobsOf(d), { on: DEPLOY_ON }));
    const r = await judge([unsigned], d);
    expect(r.issues.some((i) => /published unsigned/.test(i.message)), show(r)).toBe(true);
    // with the attest sign job the unsigned-publish rule is satisfied
    const [file] = attestSet(d) as [CreatedFile];
    const r2 = await judge([file, withPublish(base)], d);
    expect(r2.issues.some((i) => /published unsigned/.test(i.message)), show(r2)).toBe(false);
  });
});
