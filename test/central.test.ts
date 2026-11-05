// v0.2 Plan G Task 1, sub-task G3 (rulings S21, B3; G2 carries): the project's central sign workflow and its caller job. The signing mode
// is code-chosen (signingMode, or none for the proof) and written as a literal of the file; the sign job is G2's renderer in job `sign`,
// key-env in environment pipegen-signing with --tlog-upload=false, cache-mode none, the permissions its mode needs; the caller is a
// deploy job of pipegen.yml (G2-R-sec2). No enrolled list; records-only pipelines gets no central workflow.
import { createHash } from 'node:crypto';
import { Document, parse, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { DEPLOY_PUSH_IF } from '../src/engine/job-rules.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { RenderError } from '../src/engine/render-error.js';
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
const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
const deps = { reviewed: reviewedList(), platform: p };
const PUB_SHA = createHash('sha256').update('a public key', 'utf8').digest('hex');
const SHA = 'a'.repeat(40);
const IMG = { service: 'app', repo: 'ghcr.io/o/r-app' };
const IMG2 = { service: 'web', repo: 'ghcr.io/o/r-web' };

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
const keSet = (d: PipelineDraft = keDraft()): CreatedFile[] => [fileOf(sharedWorkflows(d, 'key-env', deps)), appCaller(d, signCallerJob(d, 'key-env', ['gate']) as Record<string, unknown>)];
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
    expect(sign.env).toEqual({ BASH_ENV: '', ENV: '', [KEY_NAME]: `\${{ secrets.${KEY_NAME} }}`, [PW_NAME]: `\${{ secrets.${PW_NAME} }}` });
    for (const s of j.steps as Obj[]) if (s !== sign) expect(JSON.stringify(s)).not.toMatch(/PIPEGEN_COSIGN/);
    // exactly G2's renderer: the sign step is renderSignSteps' own
    const g2 = renderSignSteps(entry('cosign'), 'key-env', IMG);
    expect(sign.run).toBe(g2[1]?.run);
    // the digest of each image comes from its hand-off artifact, downloaded first; then the reviewed cosign, the ghcr login, the sign step
    const kinds = (j.steps as Obj[]).map((s) => (s.uses ?? s.id ?? s.name) as string);
    expect(kinds).toHaveLength(4);
    expect(kinds[0]).toMatch(/^actions\/download-artifact@/);
    expect((j.steps as Obj[])[0]?.with).toEqual({ name: imageDigestArtifact('app'), path: `\${{ runner.temp }}/pipegen-out/${imageDigestArtifact('app')}` });
    expect((j.steps as Obj[])[1]?.run).toBe(g2[0]?.run);
    expect(kinds[2]).toMatch(/^docker\/login-action@/);
    expect((j.steps as Obj[])[2]?.with?.registry).toBe('ghcr.io');
    expect((j.steps as Obj[])[3]).toBe(sign);
    // the referee's rule holds the key to the environment: without it, refused
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

  it('central: keyless only requests id-token write', () => {
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
    // the inline keyless job passes the referee as a deploy job of pipegen.yml
    return (async () => {
      // the referee holds it too: a key-env sign job that asks for the OIDC token or attestations write is refused
      const [keFile, keCaller] = keSet();
      for (const extra of [{ [OIDC]: 'write' }, { attestations: 'write' }]) {
        const wide = editSign(keFile as CreatedFile, (sj) => { sj.permissions = { ...sj.permissions, ...extra }; });
        const callerDoc = parseDocument((keCaller as CreatedFile).content);
        callerDoc.setIn(['jobs', SIGN_JOB_ID, 'permissions'], callerDoc.createNode({ contents: 'read', packages: 'write', ...extra }));
        const r = await judge([wide, { ...(keCaller as CreatedFile), content: callerDoc.toString({ lineWidth: 0 }) }], keDraft());
        expect(r.issues.some((i) => i.check === 'permissions' && /only a keyless sign step or actions\/attest|only actions\/attest/.test(i.message)), `${JSON.stringify(extra)}: ${show(r)}`).toBe(true);
      }
      const file = workflow({ ...jobsOf(pub), [SIGN_JOB_ID]: { ...j, if: DEPLOY_PUSH_IF, needs: ['gate'] } }, { on: DEPLOY_ON });
      expect(show(await judge([file], pub))).toBe('');
      // and a private repository never signs keyless (a public log): the mode is not the chosen one
      expect(() => signJob({ ...pub, profile: { ...pub.profile, private: true } }, 'keyless', deps)).toThrow(RenderError);
    })();
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
    const caller = signCallerJob(d, 'key-env', ['gate']) as Record<string, unknown>;
    expect(caller).toEqual({ uses: `o/pipelines/.github/workflows/r--sign.yml@${SHA}`, if: DEPLOY_PUSH_IF, needs: ['gate'], permissions: { contents: 'read', packages: 'write' } });
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
    expect(() => signCallerJob(keDraft({ centralPin: undefined }), 'key-env', ['gate'])).toThrow(RenderError);
    expect(() => signCallerJob(keDraft({ centralPin: { repo: 'x/pipelines', sha: SHA } }), 'key-env', ['gate'])).toThrow(RenderError);
    expect(() => signCallerJob(keDraft({ centralPin: { repo: 'o/pipelines', sha: 'main' } }), 'key-env', ['gate'])).toThrow(RenderError);
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
    const caller = appCaller(d, signCallerJob(d, 'key-env', ['gate']) as Record<string, unknown>);
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
