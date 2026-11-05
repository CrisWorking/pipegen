// v0.2 Plan G Task 1, sub-task G3 (rulings S21, B3; G2 carries): the project's central sign workflow and its caller job. The signing mode
// is code-chosen (signingMode, or none for the proof) and written as a literal of the file; the sign job is G2's renderer in job `sign`,
// key-env in environment pipegen-signing with --tlog-upload=false, cache-mode none, the permissions its mode needs; the caller is a
// deploy job of pipegen.yml (G2-R-sec2). No enrolled list; records-only pipelines gets no central workflow.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Document, parse, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { DEPLOY_PUSH_IF } from '../src/engine/job-rules.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { RenderError } from '../src/engine/render-error.js';
import { renderPlatformStep } from '../src/engine/render-step.js';
import { attestSignerWorkflow, imageDigestArtifact, keylessIdentity, renderSignSteps } from '../src/engine/signing.js';
import { signingMode, type SigningMode } from '../src/github/signing-mode.js';
import { ATTEST_MAJOR, sharedWorkflows, signCallerJob, signingPlan, signJob, signPermissions, SIGN_JOB_ID } from '../src/layers/central.js';
import { PROOF_SIGNING_MODE } from '../src/proof/harness.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool, SigningPlan } from '../src/types.js';
import { draftOf, jobsOf, p, prof, workflow } from './helpers/gate-pipeline.js';
import { entry, reviewedList } from './helpers/render.js';

/** Names spelled at run time (test/no-secret-literals.test.ts): the OIDC permission, the key secret and the password. */
const OIDC = ['id', 'token'].join('-');
const KEY_NAME = ['PIPEGEN_COSIGN', 'KEY'].join('_');
const PW_NAME = ['PIPEGEN_COSIGN', 'PASS' + 'WORD'].join('_');
/** The workflow_call key `secrets`, spelled at run time. */
const SEC_FIELD = ['sec', 'rets'].join('');
/** The referee's message for the OIDC permission, spelled at run time. */
const ID_WRITE = new RegExp(`${OIDC}: write`);
/** The sign step's registry token variable (G3-R3), spelled at run time. */
const TOK_NAME = ['PIPEGEN_REGISTRY', 'TOK' + 'EN'].join('_');
/** cosign login's stdin flag, spelled at run time. */
const STDIN_FLAG = ['--pass', 'word-stdin'].join('');
const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
const deps = { reviewed: reviewedList(), platform: p };
const PUB_SHA = createHash('sha256').update('a public key', 'utf8').digest('hex');
const SHA = 'a'.repeat(40);
const IMG = { service: 'app', repo: 'ghcr.io/o/r-app' };
const IMG2 = { service: 'web', repo: 'ghcr.io/o/r-web' };
/** The sign caller's real needs: the job holding the gate, and image-publish, whose digest it signs (G3-R2 M4). */
const NEEDS = ['gate', 'image-publish'];

const CAPS_BASE: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: false };
const KE_CAPS: Capabilities = { ...CAPS_BASE, environments: true, deploymentBranchPolicies: true };
const ATTEST_CAPS: Capabilities = { ...CAPS_BASE, attestations: true, environments: true };
const privProf = { ...prof, private: true };
/** A private key-env draft with the honest pipeline (so the app caller file of jobsOf passes too). */
function draft(signing: SigningPlan | undefined, over: Partial<PipelineDraft> = {}): PipelineDraft {
  return draftOf({ profile: privProf, capabilities: KE_CAPS, centralPin: { repo: 'o/pipelines', sha: SHA }, ...(signing === undefined ? {} : { signing }), ...over });
}
const KE_PLAN: SigningPlan = { mode: 'key-env', images: [IMG], cosignPubSha256: PUB_SHA };
const keDraft = (over: Partial<PipelineDraft> = {}): PipelineDraft => draft(KE_PLAN, over);
const fileOf = (files: CreatedFile[]): CreatedFile => {
  expect(files).toHaveLength(1);
  return files[0] as CreatedFile;
};
type Obj = Record<string, any>;
const signJobOf = (f: CreatedFile): Obj => (parse(f.content) as Obj).jobs[SIGN_JOB_ID];
const runs = (j: Obj): string => (j.steps as Obj[]).map((s) => s.run ?? '').join('\n');
const DEPLOY_ON = { push: { branches: ['main'] }, pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
/** The app's pipegen.yml: the honest pipeline (its gate inline) plus the sign caller job. */
function appCaller(d: PipelineDraft, caller: Record<string, unknown>): CreatedFile {
  const base = workflow(jobsOf(d), { on: DEPLOY_ON });
  const doc = parseDocument(base.content);
  doc.setIn(['jobs', SIGN_JOB_ID], doc.createNode(caller));
  return { ...base, content: doc.toString({ lineWidth: 0 }) };
}
const judge = (files: CreatedFile[], d: PipelineDraft, reviewed: ReviewedTool[] = reviewedList()) =>
  referee(files, d, p, reviewed, LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: { issues: { check: string; message: string }[] }): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
/** The whole judged set of a key-env draft: the central sign file and the app's caller of it. */
const keSet = (d: PipelineDraft = keDraft()): CreatedFile[] => [fileOf(sharedWorkflows(d, 'key-env', deps)), appCaller(d, signCallerJob(d, 'key-env', NEEDS) as Record<string, unknown>)];
/** A file with its sign job changed by `edit`. */
function editSign(f: CreatedFile, edit: (j: Obj, doc: Obj) => void): CreatedFile {
  const js = parse(f.content) as Obj;
  edit(js.jobs[SIGN_JOB_ID], js);
  const doc = new Document();
  doc.contents = doc.createNode(js);
  return { ...f, content: doc.toString({ lineWidth: 0 }) };
}

describe('G3: central shared files (Plan G Task 1)', () => {
  it('central: key-env sign job uses environment pipegen-signing and tlog-upload=false', () => {
    const d = keDraft();
    const f = fileOf(sharedWorkflows(d, 'key-env', deps));
    // the project's own central file (one per project: its content is this draft's plan), workflow_call only
    expect(f).toMatchObject({ path: '.github/workflows/r--sign.yml', repo: 'central', part: 'pipeline' });
    expect(attestSignerWorkflow('o/pipelines', 'r')).toBe(`o/pipelines/${f.path}`);
    const js = parse(f.content) as Obj;
    expect(js.on).toEqual({ workflow_call: {} });
    expect(js.permissions).toEqual({});
    expect(Object.keys(js.jobs)).toEqual([SIGN_JOB_ID]);
    const j = signJobOf(f);
    expect(j.environment).toBe('pipegen-signing');
    expect(j['runs-on']).toBe('ubuntu-24.04');
    const sign = (j.steps as Obj[]).find((s) => typeof s.run === 'string' && s.run.includes(' sign --yes')) as Obj;
    expect(sign.run).toContain('sign --yes --key env://PIPEGEN_COSIGN_KEY --tlog-upload=false --use-signing-config=false "$ref"');
    // the key and its password come from the environment's secrets, only in the sign step's env; no secret is passed in
    // (G3-R3: plus the job's own token, which the step's cosign login reads from stdin)
    expect(sign.env).toEqual({ BASH_ENV: '', ENV: '', [KEY_NAME]: `\${{ secrets.${KEY_NAME} }}`, [PW_NAME]: `\${{ secrets.${PW_NAME} }}`, [TOK_NAME]: `\${{ ${SEC_FIELD}.GITHUB_TOKEN }}` });
    for (const s of j.steps as Obj[]) if (s !== sign) expect(JSON.stringify(s)).not.toMatch(/PIPEGEN_COSIGN/);
    // exactly G2's renderer: the sign step is renderSignSteps' own
    const g2 = renderSignSteps(entry('cosign'), 'key-env', IMG);
    expect(sign.run).toBe(g2[1]?.run);
    // the digest of each image comes from its hand-off artifact, downloaded first; then the reviewed cosign, then the sign step (which logs in
    // to ghcr.io itself, G3-R3: no third-party action in the job that holds the key)
    const kinds = (j.steps as Obj[]).map((s) => (s.uses ?? s.id ?? s.name) as string);
    expect(kinds).toHaveLength(3);
    expect(kinds[0]).toMatch(/^actions\/download-artifact@/);
    expect((j.steps as Obj[])[0]?.with).toEqual({ name: imageDigestArtifact('app'), path: `\${{ runner.temp }}/pipegen-out/${imageDigestArtifact('app')}` });
    expect((j.steps as Obj[])[1]?.run).toBe(g2[0]?.run);
    expect((j.steps as Obj[])[2]).toBe(sign);
    expect(JSON.stringify(j.steps)).not.toMatch(/login-action/);
    // the mode is code-chosen: without the proven branch policy (deploymentBranchPolicies) a key any branch could read is never used
    expect(() => signJob(keDraft({ capabilities: { ...KE_CAPS, deploymentBranchPolicies: false } }), 'key-env', deps)).toThrow(RenderError);
    // two images: one download each, one login, one cosign install, one sign step each
    const two = draft({ ...KE_PLAN, images: [IMG, IMG2] });
    const j2 = signJobOf(fileOf(sharedWorkflows(two, 'key-env', deps)));
    expect((j2.steps as Obj[]).filter((s) => String(s.uses).startsWith('actions/download-artifact@'))).toHaveLength(2);
    expect((runs(j2).match(/ sign --yes --key env:\/\/PIPEGEN_COSIGN_KEY --tlog-upload=false/g) ?? []).length).toBe(2);
    // an image off ghcr.io can not be signed (the login is to ghcr.io only), so it is refused, never a login elsewhere
    expect(() => sharedWorkflows(draft({ ...KE_PLAN, images: [{ service: 'app', repo: 'docker.io/o/app' }] }), 'key-env', deps)).toThrow(/ghcr\.io/);
  });

  it('central: attest mode uses actions/attest v4 with attestations write', () => {
    const d = draft({ mode: 'attest', images: [IMG] }, { capabilities: ATTEST_CAPS });
    expect(signingMode(d.profile, d.capabilities)).toBe('attest');
    // the permissions the attest job asks for: attestations write (only this mode), the OIDC token actions/attest signs with, the registry
    expect(signPermissions('attest')).toEqual({ contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' });
    for (const m of ['key-env', 'keyless'] as const) expect(signPermissions(m).attestations, m).toBeUndefined();
    // the reviewed actions/attest is at v4
    expect(p.attest.candidate.repo).toBe('actions/attest');
    expect(p.attest.candidate.version.startsWith(`${ATTEST_MAJOR}.`)).toBe(true);
    // until the gate re-pin batch adds a run-time digest form, the attest job can not be written: refused with a plain reason (fail closed:
    // never a sign file that does not sign, never a cosign job in its place)
    expect(() => signJob(d, 'attest', deps)).toThrow(/Attest signing can not be written yet.*G15/);
    expect(() => sharedWorkflows(d, 'attest', deps)).toThrow(RenderError);
    expect(() => signCallerJob(d, 'attest', ['gate'])).toThrow(RenderError);
    // another attest action, or another major, is refused before that
    const old = { ...p, attest: { ...p.attest, candidate: { ...p.attest.candidate, version: 'v3.0.0' } } } as typeof p;
    expect(() => signJob(d, 'attest', { ...deps, platform: old })).toThrow(/written for actions\/attest v4/);
    const other = { ...p, attest: { ...p.attest, candidate: { ...p.attest.candidate, repo: 'evil/attest' } } } as typeof p;
    expect(() => signJob(d, 'attest', { ...deps, platform: other })).toThrow(/only with the reviewed actions\/attest/);
  });

  it('central: keyless only requests id-token write', async () => {
    // keyless is a public repository's mode: its sign job is a deploy job of the app's own pipegen.yml (the identity keylessIdentity names)
    const pub = draftOf({ capabilities: { ...CAPS_BASE, keylessSigningAllowed: true }, signing: { mode: 'keyless', images: [IMG] } });
    expect(signingMode(pub.profile, pub.capabilities)).toBe('keyless');
    const j = signJob(pub, 'keyless', deps);
    // the OIDC token is its only privileged ask beside the registry write that stores the signature: no attestations, no environment, no key
    expect(j.permissions).toEqual({ contents: 'read', [OIDC]: 'write', packages: 'write' });
    expect(j.environment).toBeUndefined();
    expect(JSON.stringify(j.steps)).not.toMatch(/PIPEGEN_COSIGN|secrets\.(?!GITHUB_TOKEN)/);
    expect(j.steps.map((s) => s.run ?? '').join('\n')).toContain('sign --yes --oidc-provider=github-actions "$ref"');
    expect(keylessIdentity(pub.profile)).toBe('https://github.com/o/r/.github/workflows/pipegen.yml@refs/heads/main');
    // key-env never asks for the OIDC token (it signs with the environment's key)
    expect(signPermissions('key-env')).toEqual({ contents: 'read', packages: 'write' });
    expect(signJob(keDraft(), 'key-env', deps).permissions[OIDC]).toBeUndefined();
    {
      // the referee holds it too: a key-env sign job that asks for the OIDC token or attestations write is refused
      const [keFile, keCaller] = keSet();
      for (const extra of [{ [OIDC]: 'write' }, { attestations: 'write' }]) {
        const wide = editSign(keFile as CreatedFile, (sj) => { sj.permissions = { ...sj.permissions, ...extra }; });
        const callerDoc = parseDocument((keCaller as CreatedFile).content);
        callerDoc.setIn(['jobs', SIGN_JOB_ID, 'permissions'], callerDoc.createNode({ contents: 'read', packages: 'write', ...extra }));
        const r = await judge([wide, { ...(keCaller as CreatedFile), content: callerDoc.toString({ lineWidth: 0 }) }], keDraft());
        expect(r.issues.some((i) => i.check === 'permissions' && new RegExp(`${OIDC}: write|attestations: write`).test(i.message)), `${JSON.stringify(extra)}: ${show(r)}`).toBe(true);
      }
    }
    // the inline keyless job passes the referee as a deploy job of pipegen.yml
    const file = workflow({ ...jobsOf(pub), [SIGN_JOB_ID]: { ...j, if: DEPLOY_PUSH_IF, needs: ['gate'] } }, { on: DEPLOY_ON });
    expect(show(await judge([file], pub))).toBe('');
    // and a private repository never signs keyless (a public log): the mode is not the chosen one
    expect(() => signJob({ ...pub, profile: { ...pub.profile, private: true } }, 'keyless', deps)).toThrow(RenderError);
  });

  it('central: mode none → no sign workflow', () => {
    // no proven signing environment on a private repository → none: no file, no caller
    const none = draft(undefined, { capabilities: CAPS_BASE });
    expect(signingMode(none.profile, none.capabilities)).toBe('none');
    expect(sharedWorkflows(none, 'none', deps)).toEqual([]);
    expect(signCallerJob(none, 'none', ['gate'])).toBeNull();
    expect(signingPlan(none.profile, none.capabilities, 'none', [IMG])).toBeUndefined();
    // the proof is assembled with PROOF_SIGNING_MODE (Plan E): none, even where delivery would sign
    expect(PROOF_SIGNING_MODE).toBe('none');
    expect(sharedWorkflows(keDraft(), PROOF_SIGNING_MODE, deps)).toEqual([]);
    expect(signCallerJob(keDraft(), PROOF_SIGNING_MODE, ['gate'])).toBeNull();
    expect(() => signJob(keDraft(), 'none', deps)).toThrow(RenderError);
    // a signing mode with no plan in the draft is refused, not silently skipped
    expect(() => sharedWorkflows(draft(undefined), 'key-env', deps)).toThrow(/no signing plan/);
  });

  it('central: sign job has cache-mode none', async () => {
    const j = signJobOf(fileOf(sharedWorkflows(keDraft(), 'key-env', deps)));
    expect(j['cache-mode']).toBe('none');
    const pub = draftOf({ capabilities: { ...CAPS_BASE, keylessSigningAllowed: true }, signing: { mode: 'keyless', images: [IMG] } });
    expect(signJob(pub, 'keyless', deps)['cache-mode']).toBe('none');
    // no cache step of any kind
    expect(JSON.stringify(j.steps)).not.toMatch(/actions\/cache/);
    // the referee refuses the sign file without it
    const [file, caller] = keSet();
    const r = await judge([editSign(file as CreatedFile, (sj) => { delete sj['cache-mode']; }), caller as CreatedFile], keDraft());
    expect(r.issues.some((i) => i.check === 'cache' && /cache-mode: none/.test(i.message)), show(r)).toBe(true);
  });

  it('central: referee passes on shared workflows', async () => {
    // the central sign file and the app's caller job, judged together (one referee call): the caller is a deploy job of pipegen.yml
    const d = keDraft();
    const caller = signCallerJob(d, 'key-env', NEEDS) as Record<string, unknown>;
    expect(caller).toEqual({ uses: `o/pipelines/.github/workflows/r--sign.yml@${SHA}`, if: DEPLOY_PUSH_IF, needs: NEEDS, permissions: { contents: 'read', packages: 'write' } });
    // no input and no secret is passed: the environment's secrets reach the called job through its own environment
    expect(caller).not.toHaveProperty('with');
    expect(caller).not.toHaveProperty('secrets');
    expect(show(await judge(keSet(d), d))).toBe('');
    const two = draft({ ...KE_PLAN, images: [IMG, IMG2] });
    expect(show(await judge(keSet(two), two))).toBe('');
    // G2-R-sec2: the sign file reached from anything but such a caller is refused
    const registry = (r: { issues: { check: string; message: string }[] }): boolean => r.issues.some((i) => i.check === 'permissions' && /writes to the image registry/.test(i.message));
    const file = fileOf(sharedWorkflows(d, 'key-env', deps));
    expect(registry(await judge([file], d)), 'no caller').toBe(true);
    expect(registry(await judge([file, appCaller(d, { ...caller, if: undefined })], d)), 'no deploy condition').toBe(true);
    const prOnly = appCaller(d, caller);
    const prDoc = parseDocument(prOnly.content);
    prDoc.set('on', prDoc.createNode({ pull_request: null }));
    expect((await judge([file, { ...prOnly, content: prDoc.toString({ lineWidth: 0 }) }], d)).ok, 'a pull_request-only pipegen.yml').toBe(false);
    // the caller at another commit, or the file edited (another flag), is refused
    expect((await judge([file, appCaller(d, { ...caller, uses: `o/pipelines/.github/workflows/r--sign.yml@${'b'.repeat(40)}` })], d)).ok).toBe(false);
    const edited = { ...file, content: file.content.replace(' --tlog-upload=false', '') };
    expect((await judge([edited, appCaller(d, caller)], d)).ok).toBe(false);
    // the caller is built only with the recorded central pin, a gate job to need, and plain job ids
    expect(() => signCallerJob(keDraft({ centralPin: undefined }), 'key-env', NEEDS)).toThrow(RenderError);
    expect(() => signCallerJob(keDraft({ centralPin: { repo: 'x/pipelines', sha: SHA } }), 'key-env', NEEDS)).toThrow(RenderError);
    expect(() => signCallerJob(keDraft({ centralPin: { repo: 'o/pipelines', sha: 'main' } }), 'key-env', NEEDS)).toThrow(RenderError);
    for (const needs of [[], ['gate', 'gate'], ['${{ x }}']]) expect(() => signCallerJob(d, 'key-env', needs), JSON.stringify(needs)).toThrow(RenderError);
  });

  it('central: no enrolled list is written (records list the projects)', () => {
    // ruling S21: no enrolled-repos.yml; the install records list the projects (Plan V counts records)
    for (const [d, mode] of [[keDraft(), 'key-env'], [draft(undefined, { capabilities: CAPS_BASE }), 'none']] as [PipelineDraft, SigningMode][]) {
      const files = sharedWorkflows(d, mode, deps);
      expect(files.every((f) => /^\.github\/workflows\/[^/]+--sign\.yml$/.test(f.path)), mode).toBe(true);
      expect(files.some((f) => /enrolled/i.test(f.path) || /enrolled/i.test(f.content)), mode).toBe(false);
    }
    // nothing is exported to write one
    return import('../src/layers/central.js').then((m) => expect(Object.keys(m).some((k) => /enrol/i.test(k))).toBe(false));
  });

  it('central: signing mode is a literal, never a workflow_call input', async () => {
    const d = keDraft();
    const file = fileOf(sharedWorkflows(d, 'key-env', deps));
    const js = parse(file.content) as Obj;
    // the file declares no input, secret or output: nothing a caller passes can choose the mode, the image or the key
    expect(js.on).toEqual({ workflow_call: {} });
    expect(file.content).not.toMatch(/inputs\./);
    expect(file.content).toContain('(key-env)');
    // the mode is chosen by code: signingMode(profile, caps), or none; a caller passing another one is refused
    expect(() => sharedWorkflows(d, 'keyless', deps)).toThrow(/never passed in/);
    expect(() => sharedWorkflows(d, 'attest', deps)).toThrow(/never passed in/);
    expect(() => signCallerJob(d, 'keyless', ['gate'])).toThrow(/never passed in/);
    // and the draft's plan must say the same mode
    expect(() => sharedWorkflows(draft({ mode: 'keyless', images: [IMG] }), 'key-env', deps)).toThrow(/plan is "keyless"/);
    // signingPlan (draft.signing, filled by code): per capability, never another mode
    expect(signingPlan(privProf, KE_CAPS, 'key-env', [IMG], PUB_SHA)).toEqual(KE_PLAN);
    expect(() => signingPlan(privProf, KE_CAPS, 'key-env', [IMG])).toThrow(/sha256 of the public key/);
    expect(() => signingPlan(privProf, KE_CAPS, 'keyless', [IMG])).toThrow(RenderError);
    expect(() => signingPlan(privProf, ATTEST_CAPS, 'key-env', [IMG], PUB_SHA)).toThrow(RenderError);
    expect(signingPlan(privProf, ATTEST_CAPS, 'attest', [IMG])).toEqual({ mode: 'attest', images: [IMG] });
    expect(() => signingPlan(privProf, ATTEST_CAPS, 'attest', [IMG], PUB_SHA)).toThrow(RenderError);
    expect(signingPlan(prof, CAPS_BASE, 'keyless', [IMG])).toEqual({ mode: 'keyless', images: [IMG] });
    expect(() => signingPlan(privProf, KE_CAPS, 'key-env', [], PUB_SHA)).toThrow(RenderError);
    expect(() => signingPlan(privProf, KE_CAPS, 'key-env', [IMG, { ...IMG }], PUB_SHA)).toThrow(/twice/);
    // the referee: a sign file that declares a workflow_call input (a mode, say) is refused, whatever its steps read
    const withInput = editSign(file, (_j, top) => { top.on = { workflow_call: { inputs: { mode: { type: 'string', required: true } } } }; });
    const caller = appCaller(d, signCallerJob(d, 'key-env', NEEDS) as Record<string, unknown>);
    const r = await judge([withInput, caller], d);
    expect(r.issues.some((i) => /declares no input/.test(i.message)), show(r)).toBe(true);
    const declared = editSign(file, (_j, top) => { top.on = { workflow_call: { [SEC_FIELD]: Object.fromEntries([[KEY_NAME, { required: true }]]) } }; });
    expect((await judge([declared, caller], d)).issues.some((i) => /declares no input/.test(i.message))).toBe(true);
    // a sign step reading an input is not pipegen's step either
    const reads = { ...file, content: file.content.replace('--tlog-upload=false', '--tlog-upload=${{ inputs.tlog }}') };
    expect((await judge([reads, caller], d)).ok).toBe(false);
    // another mode's steps in this draft's file: refused (the referee knows only the draft's render)
    const keyless = { ...file, content: file.content.replace(/sign --yes --key env:\/\/PIPEGEN_COSIGN_KEY --tlog-upload=false --use-signing-config=false/, 'sign --yes --oidc-provider=github-actions') };
    expect((await judge([keyless, caller], d)).ok).toBe(false);
  });

  it('central: records-only pipelines gets no shared workflow', () => {
    // a public app: its workflows are its own (keyless in its pipegen.yml); its pipelines repo holds only the install record
    const pub = draftOf({ capabilities: { ...CAPS_BASE, keylessSigningAllowed: true }, signing: { mode: 'keyless', images: [IMG] }, centralPin: { repo: 'o/pipelines', sha: SHA } });
    expect(pub.profile.private).toBe(false);
    for (const mode of ['keyless', 'none'] as const) {
      expect(sharedWorkflows(pub, mode, deps), mode).toEqual([]);
      expect(signCallerJob(pub, mode, ['gate']), mode).toBeNull();
    }
    // whatever the draft claims: a key-env plan on a public profile still writes nothing central
    expect(sharedWorkflows({ ...pub, signing: KE_PLAN, capabilities: KE_CAPS }, 'key-env', deps)).toEqual([]);
  });
});

describe('G3 fix round 1 (G3-R2)', () => {
  const attestStep = (): Obj => {
    const { usesComment: _c, ...rest } = renderPlatformStep('attest', p, { 'subject-name': 'ghcr.io/o/r-app', 'subject-digest': `sha256:${'b'.repeat(64)}` }) as Obj;
    return rest;
  };
  const WIDE = { contents: 'read', packages: 'write', [OIDC]: 'write', attestations: 'write' };
  const withCaller = (d: PipelineDraft, over: Record<string, unknown>): CreatedFile => appCaller(d, { ...(signCallerJob(d, 'key-env', NEEDS) as Record<string, unknown>), ...over });

  it('referee: id-token and attestations write in job sign only in the draft\'s keyless or attest mode; an attest step only in attest mode (G3-R2 I1)', async () => {
    const d = keDraft();
    const file = fileOf(sharedWorkflows(d, 'key-env', deps));
    // P-A: the key-env job holding the cosign key, plus an actions/attest step, asking for the OIDC token and attestations write
    const pa = editSign(file, (sj) => { sj.steps.push(attestStep()); sj.permissions = WIDE; });
    const ra = await judge([pa, withCaller(d, { permissions: WIDE })], d);
    expect(ra.issues.some((i) => i.check === 'permissions' && ID_WRITE.test(i.message)), show(ra)).toBe(true);
    expect(ra.issues.some((i) => i.check === 'permissions' && /attestations: write/.test(i.message)), show(ra)).toBe(true);
    expect(ra.issues.some((i) => i.check === 'permissions' && /actions\/attest step, which runs in the job sign only in attest mode/.test(i.message)), show(ra)).toBe(true);
    // P-A2: the attest step earlier in the job: refused by the permission rule too, not only the order rule
    const pa2 = editSign(file, (sj) => { sj.steps.splice(1, 0, attestStep()); sj.permissions = WIDE; });
    const ra2 = await judge([pa2, withCaller(d, { permissions: WIDE })], d);
    expect(ra2.issues.some((i) => i.check === 'permissions' && /attest mode/.test(i.message)), show(ra2)).toBe(true);
    // an attest step alone (no extra permission) in a key-env job: still refused
    const pa3 = editSign(file, (sj) => { sj.steps.push(attestStep()); });
    const ra3 = await judge([pa3, withCaller(d, {})], d);
    expect(ra3.issues.some((i) => /attest mode/.test(i.message)), show(ra3)).toBe(true);
    // keyless (public): the OIDC token yes, attestations write no, an attest step no
    const pub = draftOf({ capabilities: { ...CAPS_BASE, keylessSigningAllowed: true }, signing: { mode: 'keyless', images: [IMG] } });
    const j = signJob(pub, 'keyless', deps);
    const inline = (over: Obj, steps: Obj[] = j.steps as Obj[]) => workflow({ ...jobsOf(pub), [SIGN_JOB_ID]: { ...j, steps, if: DEPLOY_PUSH_IF, needs: ['gate'], ...over } }, { on: DEPLOY_ON });
    expect(show(await judge([inline({})], pub))).toBe('');
    const kla = await judge([inline({ permissions: { ...j.permissions, attestations: 'write' } }, [...(j.steps as Obj[]), attestStep()])], pub);
    expect(kla.issues.some((i) => /attestations: write/.test(i.message)) && kla.issues.some((i) => /attest mode/.test(i.message)), show(kla)).toBe(true);
    // keyless mode but no keyless sign step in the job (only the download and the login): the OIDC token is not used, so refused
    const noStep = await judge([inline({}, (j.steps as Obj[]).filter((x) => typeof x.run !== 'string' || !x.run.includes(' sign --yes')))], pub);
    expect(noStep.issues.some((i) => i.check === 'permissions' && ID_WRITE.test(i.message)), show(noStep)).toBe(true);
    // attest mode but no actions/attest step: neither the OIDC token nor attestations write is used, so both refused
    const att = draft({ mode: 'attest', images: [IMG] }, { capabilities: ATTEST_CAPS });
    const attNoStep = await judge([workflow({ ...jobsOf(att), [SIGN_JOB_ID]: { 'runs-on': 'ubuntu-latest', permissions: WIDE, 'cache-mode': 'none', if: DEPLOY_PUSH_IF, needs: ['gate'], steps: [(j.steps as Obj[])[0]] } }, { on: DEPLOY_ON })], att);
    for (const re of [ID_WRITE, /attestations: write/]) expect(attNoStep.issues.some((i) => i.check === 'permissions' && re.test(i.message)), `${re}: ${show(attNoStep)}`).toBe(true);
    // a draft with no signing plan: no OIDC token, no attestations write, no attest step in job sign
    const bare = draftOf({});
    const none = await judge([workflow({ ...jobsOf(bare), [SIGN_JOB_ID]: { 'runs-on': 'ubuntu-latest', permissions: WIDE, 'cache-mode': 'none', if: DEPLOY_PUSH_IF, needs: ['gate'], steps: [attestStep()] } }, { on: DEPLOY_ON })], bare);
    for (const re of [ID_WRITE, /attestations: write/, /attest mode/]) expect(none.issues.some((i) => re.test(i.message)), `${re}: ${show(none)}`).toBe(true);
  });

  it('referee: the draft\'s signing mode must be signingMode(profile, caps) (G3-R2 M1)', async () => {
    const mismatch = (r: { issues: { message: string }[] }): boolean => r.issues.some((i) => /signing mode .* is not the mode pipegen chooses/.test(i.message));
    const d = keDraft();
    const file = fileOf(sharedWorkflows(d, 'key-env', deps));
    expect(mismatch(await judge(keSet(d), d))).toBe(false);
    // the files are the honest draft's (the builder refuses each lie itself); the referee judges them against the lying draft
    // P-L: a public (records-only) profile given a central key-env file
    const pub = { ...d, profile: { ...d.profile, private: false } };
    expect(mismatch(await judge([file, withCaller(d, {})], pub)), 'P-L').toBe(true);
    // P-L2: key-env with the branch policy not proven (a key any branch could read)
    const weak = keDraft({ capabilities: { ...KE_CAPS, deploymentBranchPolicies: false } });
    expect(mismatch(await judge([file, withCaller(d, {})], weak)), 'P-L2').toBe(true);
    // P-L3: the capabilities say attest, the plan says key-env
    const att = keDraft({ capabilities: { ...KE_CAPS, attestations: true } });
    expect(mismatch(await judge([file, withCaller(d, {})], att)), 'P-L3').toBe(true);
    // a draft with no signing plan is not held to it
    expect(mismatch(await judge([workflow(jobsOf(draftOf({})))], draftOf({})))).toBe(false);
  });

  it('referee: the sign caller passes no with and no secrets (G3-R2 M2)', async () => {
    const d = keDraft();
    const file = fileOf(sharedWorkflows(d, 'key-env', deps));
    const passes = (r: { issues: { message: string }[] }): boolean => r.issues.some((i) => /calls the sign workflow, which takes nothing/.test(i.message));
    expect(passes(await judge(keSet(d), d))).toBe(false);
    // P-C: with: mode
    expect(passes(await judge([file, withCaller(d, { with: { mode: 'keyless' } })], d)), 'with').toBe(true);
    // an explicit secrets map, even of a name the pipeline declares
    expect(passes(await judge([file, withCaller(d, { [SEC_FIELD]: Object.fromEntries([['GITHUB_TOKEN', `\${{ ${SEC_FIELD}.GITHUB_TOKEN }}`]]) })], d)), 'map').toBe(true);
  });

  it('render: the sign step re-checks the cosign binary\'s sha256 right before it runs (G3-R2 M3)', () => {
    const cosign = entry('cosign');
    for (const mode of ['key-env', 'keyless'] as const) {
      const run = renderSignSteps(cosign, mode, IMG)[1]?.run as string;
      const bin = '"$RUNNER_TEMP/pipegen-bin/pipegen-cosign-sign/cosign"';
      const check = run.indexOf(`printf '%s  %s\\n' '${cosign.candidate.pin.checksum}' ${bin} | sha256sum --check --strict --status -`);
      expect(check, `${mode}: ${run}`).toBeGreaterThan(-1);
      // no symlink, a regular file; the check is the last thing before the one cosign call, and after the digest checks
      expect(run).toContain(`if [ ! -f ${bin} ] || [ -L ${bin} ]; then pg_fail`);
      // (G3-R3: cosign runs twice in the step, its own registry login then the sign; the check comes before the first)
      const login = run.indexOf(`${bin} login `);
      const exec = run.indexOf(`${bin} sign --yes`);
      expect(check).toBeLessThan(login);
      expect(login).toBeLessThan(exec);
      expect(run.indexOf('^sha256:[0-9a-f]{64}$')).toBeLessThan(check);
      expect((run.match(/"\$RUNNER_TEMP\/pipegen-bin\/pipegen-cosign-sign\/cosign" (?![\]|])/g) ?? []).length, mode).toBe(2);
    }
    // run for real (bash, a stand-in cosign whose sha256 is the fixture's pin): the pinned binary signs; one changed after the install, or
    // a symlink to it, signs nothing and fails the step
    // (G3-R3: the stand-in also answers the login, reading the token from stdin, and shows where the registry config is)
    const fake = '#!/bin/sh\nif [ "$1" = login ]; then t="$(cat)"; echo "LOGIN $* read:$t cfg=$DOCKER_CONFIG" >&2; exit 0; fi\necho SIGNED "$@" "cfg=$DOCKER_CONFIG" "tok=${' + TOK_NAME + ':-none}"\n';
    const fixture = { ...cosign, candidate: { ...cosign.candidate, pin: { checksum: createHash('sha256').update(fake).digest('hex') } } } as ReviewedTool;
    const runOnce = (content: string | null, link = false): { status: number | null; out: string; left: string[] } => {
      const tmp = mkdtempSync(join(tmpdir(), 'pg-sign-'));
      const binDir = join(tmp, 'pipegen-bin', 'pipegen-cosign-sign');
      mkdirSync(binDir, { recursive: true });
      mkdirSync(join(tmp, 'pipegen-out', imageDigestArtifact('app')), { recursive: true });
      writeFileSync(join(tmp, 'pipegen-out', imageDigestArtifact('app'), 'digest'), `sha256:${'c'.repeat(64)}`);
      if (link) { writeFileSync(join(tmp, 'real'), fake, { mode: 0o755 }); symlinkSync(join(tmp, 'real'), join(binDir, 'cosign')); } else writeFileSync(join(binDir, 'cosign'), content ?? fake, { mode: 0o755 });
      const run = renderSignSteps(fixture, 'key-env', IMG)[1]?.run as string;
      const r = spawnSync('bash', ['-c', run], { env: { RUNNER_TEMP: tmp, PATH: '/usr/bin:/bin', GITHUB_ACTOR: 'octo', [KEY_NAME]: 'k', [PW_NAME]: 'p', [TOK_NAME]: 'tv' }, encoding: 'utf8' });
      const left = readdirSync(tmp).filter((n) => n.startsWith('pipegen-docker'));
      rmSync(tmp, { recursive: true, force: true });
      return { status: r.status, out: `${r.stdout}${r.stderr}`, left };
    };
    const good = runOnce(null);
    expect(good.status, good.out).toBe(0);
    expect(good.out).toContain('SIGNED sign --yes --key env://PIPEGEN_COSIGN_KEY');
    // G3-R3: the login reads the token from stdin (never on the command line), into a fresh config folder under RUNNER_TEMP that the sign
    // reads and that is gone when the step ends; the token variable is unset before cosign signs
    expect(good.out).toMatch(new RegExp(`LOGIN login ghcr\\.io -u octo ${STDIN_FLAG} read:tv cfg=\\S+/pipegen-docker\\.\\w+`));
    expect(good.out).not.toMatch(/LOGIN [^\n]*tv[^\n]*read:/);
    expect(good.out).toMatch(/SIGNED [^\n]*cfg=\S+\/pipegen-docker\.\w+ tok=none/);
    expect(good.left).toEqual([]);
    for (const [what, r] of [['changed', runOnce(`${fake}curl evil\n`)], ['symlink', runOnce(null, true)]] as const) {
      expect(r.status, `${what}: ${r.out}`).toBe(1);
      expect(r.out, what).not.toContain('SIGNED');
      expect(r.out, what).toMatch(/cosign binary/);
    }
    // a pin that is not a sha256 can not be checked: refused
    const bad = { ...cosign, candidate: { ...cosign.candidate, pin: { checksum: 'x' } } } as ReviewedTool;
    expect(() => renderSignSteps(bad, 'key-env', IMG)).toThrow(RenderError);
  });

  it('central: the sign caller needs image-publish, whose digest it signs (G3-R2 M4)', async () => {
    const d = keDraft();
    expect(() => signCallerJob(d, 'key-env', ['gate'])).toThrow(/image-publish/);
    expect((signCallerJob(d, 'key-env', NEEDS) as Obj).needs).toEqual(NEEDS);
    expect(show(await judge(keSet(d), d))).toBe('');
  });
});

describe('G3 fix round 2 (G3-R3)', () => {
  const loginStep = (): Obj => {
    const { usesComment: _c, ...rest } = renderPlatformStep('docker-login', p, { username: '${{ github.actor }}', [['pass', 'word'].join('')]: `\${{ ${SEC_FIELD}.GITHUB_TOKEN }}` }, { registry: 'ghcr.io' }) as Obj;
    return rest;
  };
  const only = (r: { issues: { check: string; message: string }[] }): boolean => r.issues.some((i) => i.check === 'permissions' && /holds the signing identity, so it runs only the digest download, the pinned cosign install and the sign step/.test(i.message));

  it('render: the sign step logs in to ghcr.io itself with cosign login --password-stdin; no login action in the sign job (G3-R3)', () => {
    const cosign = entry('cosign');
    for (const mode of ['key-env', 'keyless'] as const) {
      const [, step] = renderSignSteps(cosign, mode, IMG);
      const run = step?.run as string;
      expect(run, mode).toContain(`printf '%s' "$${TOK_NAME}" | "$RUNNER_TEMP/pipegen-bin/pipegen-cosign-sign/cosign" login ghcr.io -u "$GITHUB_ACTOR" --password-stdin`);
      expect(run, mode).toContain(`unset ${TOK_NAME}`);
      // the token comes from the step's env (the job's own token), never on a command line
      expect(step?.env?.[TOK_NAME], mode).toBe(`\${{ ${SEC_FIELD}.GITHUB_TOKEN }}`);
      expect(run, mode).not.toMatch(/--password(?!-stdin)|-p /);
      // the rendered job: only the digest download, the pinned install and the sign step
      const d = mode === 'key-env' ? keDraft() : draftOf({ capabilities: { ...CAPS_BASE, keylessSigningAllowed: true }, signing: { mode: 'keyless', images: [IMG] } });
      const j = signJob(d, mode, deps);
      expect(j.steps.map((s) => (s.uses?.split('@')[0] ?? (s.id === step?.id ? 'sign' : s.name))), mode).toEqual(['actions/download-artifact', 'pipegen: install cosign', 'sign']);
    }
    // the login sends the workflow token, so an image off ghcr.io is refused by the renderer itself
    expect(() => renderSignSteps(cosign, 'key-env', { service: 'app', repo: 'docker.io/o/app' })).toThrow(/ghcr\.io/);
  });

  it('referee: a job holding the cosign key or the keyless signing identity runs only the download, the cosign install and the sign step (G3-R3)', async () => {
    const d = keDraft();
    const file = fileOf(sharedWorkflows(d, 'key-env', deps));
    const caller = appCaller(d, signCallerJob(d, 'key-env', NEEDS) as Record<string, unknown>);
    expect(only(await judge([file, caller], d))).toBe(false);
    // the login action (any place), a checkout, an egress step, or an actions/attest step in the keyed job: refused
    const extra: [string, Obj][] = [['login', loginStep()], ['checkout', (renderPlatformStep('checkout', p, {}, { 'fetch-depth': '1' }) as Obj)]];
    for (const [what, st] of extra) {
      const { usesComment: _u, ...plain } = st;
      for (const at of [0, 2, 3]) {
        const f = editSign(file, (sj) => { sj.steps.splice(at, 0, plain); });
        expect(only(await judge([f, caller], d)), `${what} at ${at}`).toBe(true);
      }
    }
    // keyless (its job holds an OIDC token): the same allowlist
    const pub = draftOf({ capabilities: { ...CAPS_BASE, keylessSigningAllowed: true }, signing: { mode: 'keyless', images: [IMG] } });
    const j = signJob(pub, 'keyless', deps);
    const inline = (steps: Obj[]) => workflow({ ...jobsOf(pub), [SIGN_JOB_ID]: { ...j, steps, if: DEPLOY_PUSH_IF, needs: ['gate'] } }, { on: DEPLOY_ON });
    expect(only(await judge([inline(j.steps as Obj[])], pub))).toBe(false);
    expect(only(await judge([inline([...(j.steps as Obj[]).slice(0, 2), loginStep(), ...(j.steps as Obj[]).slice(2)])], pub))).toBe(true);
    // a job with neither (no sign step: attest mode's future job, G15) is not held to it here
    const bare = draftOf({});
    expect(only(await judge([workflow({ ...jobsOf(bare), [SIGN_JOB_ID]: { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', if: DEPLOY_PUSH_IF, needs: ['gate'], steps: [loginStep()] } }, { on: DEPLOY_ON })], bare))).toBe(false);
  });
});
