// v0.2 Plan G, sub-task G2 (rulings B3 b and d, B6, S14, S30; carries C0c, C-MUST-1, CF-1, D-m4, F-4): the signing and verification
// steps (one shared renderer from the reviewed entries, each only in its own job), the PR's own image handed from image-build to the
// scanners as an archive bound by its sha256 (no registry write), the image base twin, the build-push binding, the created-path
// alphabet, the vault fallback for PIPEGEN.md, and the reviewed-list values that could narrow a blocking scan (F2-R11).
import { createHash } from 'node:crypto';
import { Document, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { GITHUB_ATTEST_SET, renderEgressStep } from '../src/engine/egress.js';
import { aiChoiceNames, CODE_FILLED_CHOICES } from '../src/create/coverage.js';
import { builderOffers } from '../src/debate/builder.js';
import { jobIdFor } from '../src/engine/gate-job-list.js';
import { CALLER_WORKFLOW, checkExpressions, checkJobOrder, defaultPushTrigger, DEPLOY_PUSH_IF, featurePushTrigger, PUSH_WORKFLOW, createdPathProblem, imageBuildJobId, jobOutputsProblems, NO_SCANS, SIGN_STEP_ENV, VERIFY_STEP_ENV, IMAGE_ARCHIVE_STEP_ID, IMAGE_SHA_OUTPUT, jobOutputsFor, NARROWING_CHOICES, WORKFLOW_CONCURRENCY, type RenderedStep } from '../src/engine/job-rules.js';
import { pipegenDoc } from '../src/deliver/docs.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { imageArchiveArtifact, imageBuildTag, renderImageArchiveScan, renderImageBuild } from '../src/engine/image-handoff.js';
import { attestSignerWorkflow, COSIGN_ID, GH_ID, imageDigestArtifact, keylessIdentity, pubKeySha256, renderSignSteps, renderVerifySteps } from '../src/engine/signing.js';
import { renderFindingsBlock, renderFindRunStep, renderJobPrelude, renderPlatformStep, renderScrub, renderStep, renderUpload, scrubbedPath, type RenderContext } from '../src/engine/render-step.js';
import { RenderError } from '../src/engine/render-error.js';
import { BUILD_PUSH_STEP_ID, PUBLISH_TAG, publishedImageRepo, renderDigestStep, renderPublishDigestStep } from '../src/engine/deploy-steps.js';
import { verifyTail, VERIFY_LIMIT } from './helpers/verify-tail.js';
import type { Candidate, CreatedFile, KnownValueCheck, Need, PipelineDraft, ReviewedTool, Service, SigningPlan, StepSpec } from '../src/types.js';
import { draftOf, GATE, imageProf, job, jobsOf, p, prof, show, workflow as stepsWorkflow, type Job } from './helpers/gate-pipeline.js';
import { entry, profile, reviewedList, service, specFor } from './helpers/render.js';

/** Names spelled at run time (test/no-secret-literals.test.ts): the OIDC permission, the password and token env names. */
/** G17 row 1b: the helper's pipegen.yml, with the workflow concurrency the two app callers carry (a called file never does). */
function workflow(jobs: Record<string, Job>, top: Record<string, unknown> = {}): CreatedFile {
  const on = top.on;
  const called = ['workflow_call', 'schedule'].some((t) => on === t || (typeof on === 'object' && on !== null && Object.hasOwn(on, t)));
  return stepsWorkflow(jobs, called ? top : { concurrency: { ...WORKFLOW_CONCURRENCY }, ...top });
}
const OIDC = ['id', 'token'].join('-');
const PW_NAME = ['PIPEGEN_COSIGN', 'PASS' + 'WORD'].join('_');
const GHT_NAME = ['PIPEGEN_GH', 'TOK' + 'EN'].join('_');
const REG_VAR = ['PIPEGEN_REGISTRY', 'TOK' + 'EN'].join('_');
const REG_TOK_NAME = ['PIPEGEN_REGISTRY', 'TOK' + 'EN'].join('_');
const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
const runWith = (files: CreatedFile[], d: PipelineDraft, reviewed: ReviewedTool[] = reviewedList(), deps: Parameters<typeof referee>[6] = {}) =>
  referee(files, d, p, reviewed, LINTERS, 'tok', { runLinters: async () => [], ...deps });
const has = (r: { issues: { check: string; message: string }[] }, check: string, re: RegExp): boolean => r.issues.some((i) => i.check === check && re.test(i.message));
const needOf = (id: string, svc?: string, blocking = true): Need => ({ id, layer: 'merge', category: id, ...(svc === undefined ? {} : { service: svc }), why: 't', blocking, floor: false });
/** A workflow written without the emitter's own checks (a hand-made file can hold what the emitter refuses; the referee must refuse it too). */
function rawFile(jobs: Record<string, Job>, top: Record<string, unknown> = {}, path = '.github/workflows/pipegen.yml'): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, { ...j, steps: ((j.steps as RenderedStep[]) ?? []).map(({ usesComment: _c, ...rest }) => rest) }]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, ...top, jobs: plain });
  return { path, content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
const lastRun = (steps: readonly RenderedStep[]): RenderedStep => [...steps].reverse().find((s) => s.run !== undefined) as RenderedStep;

// ---------- signing fixtures ----------

/** A public key's text, spelled at run time (see test/no-secret-literals.test.ts). */
const PEM = [['-----BEGIN', 'PUBLIC KEY-----'].join(' '), 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexample', [['-----END', 'PUBLIC KEY-----'].join(' ')], ''].join('\n');
const PUB_SHA = createHash('sha256').update(PEM, 'utf8').digest('hex');
const IMG = { service: 'app', repo: 'ghcr.io/o/r-app' } as const;
const COSIGN = entry(COSIGN_ID);
/** The reviewed pinned gh release entry (G15a, ruling B3 d), or a copy of it with its candidate changed (for the refusals). */
const ghEntry = (over: Partial<Candidate> = {}): ReviewedTool => {
  const real = entry(GH_ID);
  return { ...real, candidate: { ...real.candidate, ...over } as ReviewedTool['candidate'] };
};
/** A draft of only these steps (its other checks are not the point here). */
const bare = (over: Partial<PipelineDraft> = {}): PipelineDraft => draftOf({ needs: [], steps: [], ...over });
/** (G3-R2 M1: the referee holds the plan to signingMode(profile, caps), so each mode gets the repository and capabilities that choose it) */
// GJ (Plan J): the signed services build an image (imageProf: a Dockerfile each); on a service that runs nothing, signing is report-only
const MODE_SETUP: Record<SigningPlan['mode'], Partial<PipelineDraft>> = {
  'key-env': { profile: { ...imageProf, private: true }, capabilities: { ...draftOf().capabilities, environments: true, deploymentBranchPolicies: true, attestations: false } },
  keyless: { profile: imageProf, capabilities: { ...draftOf().capabilities, environments: true } },
  attest: { profile: { ...imageProf, private: true }, capabilities: { ...draftOf().capabilities, environments: true, attestations: true } },
};
const signingDraft = (signing: SigningPlan, over: Partial<PipelineDraft> = {}): PipelineDraft =>
  // (G17 row 1e: a public repository's draft carries no central pin)
  bare({ signing, ...MODE_SETUP[signing.mode], ...(MODE_SETUP[signing.mode].profile?.private === true ? { centralPin: { repo: 'o/pipelines', sha: 'a'.repeat(40) } } : {}), ...over });
const KEY_ENV: SigningPlan = { mode: 'key-env', images: [IMG], cosignPubSha256: PUB_SHA };
const KEYLESS: SigningPlan = { mode: 'keyless', images: [IMG] };
const ATTEST: SigningPlan = { mode: 'attest', images: [IMG] };
/** The digest hand-off the sign and verify steps read (image-publish uploads it; G7 brings it to the verify job). */
const digestDownload = (): RenderedStep => {
  const name = imageDigestArtifact('app');
  return renderPlatformStep('download-artifact', p, { name, path: `\${{ runner.temp }}/pipegen-out/${name}` });
};
// (G3: a key-env sign job asks for no OIDC permission, since it signs with the environment's key; only keyless or actions/attest use it)
const SIGN_PERMS = { contents: 'read', packages: 'write' };
const VERIFY_PERMS = { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' };
/** A signing draft with the honest pipeline's checks too, so a caller file of jobsOf(draft) passes. */
const withPipeline = (d: PipelineDraft): PipelineDraft => ({ ...d, needs: draftOf().needs, steps: draftOf().steps });
const DEPLOY_ON_SIGN = { push: { branches: ['main'] }, pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
/** pipegen.yml with the honest pipeline and one caller job of `uses` (deploy condition, needs gate and image-publish (G15a-R9: a sign caller needs it) unless `over` says otherwise). */
function deployCaller(d: PipelineDraft, uses: string, over: Record<string, unknown> = {}, on: unknown = DEPLOY_ON_SIGN, path = '.github/workflows/pipegen.yml'): CreatedFile {
  const base = workflow(jobsOf(d), { on });
  const doc = parseDocument(base.content);
  doc.setIn(['jobs', 'signing'], doc.createNode({ uses, if: "github.event_name == 'push'", needs: ['gate', 'image-publish'], permissions: SIGN_PERMS, ...over }));
  return { ...base, path, content: doc.toString({ lineWidth: 0 }) };
}
const signFile = (jobs: Record<string, Job>): CreatedFile => ({ ...workflow(jobs, { on: { workflow_call: null } }), path: '.github/workflows/sign.yml' });

describe('G2: signing and verification steps (B3 b, d)', () => {
  it('render: cosign sign per mode (key-env --tlog-upload=false, keyless identity) only in job sign', async () => {
    const keyEnv = renderSignSteps(COSIGN, 'key-env', IMG);
    const keyless = renderSignSteps(COSIGN, 'keyless', IMG);
    for (const steps of [keyEnv, keyless]) {
      // the reviewed cosign release, by its pinned sha256 (never a cosign from the runner)
      expect(steps[0]?.env?.PIPEGEN_DL_SHA256).toBe(COSIGN.candidate.pin.checksum);
      expect(steps[0]?.env?.PIPEGEN_DL_URL).toBe('https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64');
      const run = lastRun(steps).run as string;
      expect(run).toContain('"$RUNNER_TEMP/pipegen-bin/pipegen-cosign-sign/cosign" sign --yes');
      // the digest is read from pipegen's hand-off file and checked before anything signs it
      expect(run).toContain(`$RUNNER_TEMP/pipegen-out/${imageDigestArtifact('app')}/digest`);
      expect(run.indexOf('^sha256:[0-9a-f]{64}$')).toBeGreaterThan(-1);
      expect(run.indexOf('^sha256:[0-9a-f]{64}$')).toBeLessThan(run.indexOf(' sign --yes'));
      expect(run).toContain("ref='ghcr.io/o/r-app'\"@$digest\"");
    }
    const ke = lastRun(keyEnv);
    expect(ke.run).toContain('sign --yes --key env://PIPEGEN_COSIGN_KEY --tlog-upload=false --use-signing-config=false -a pipegen.commit="$GITHUB_SHA" "$ref"');
    // (G3-R3: both modes also carry the job's own token, which the step's cosign login reads from stdin)
    const regTok = { [REG_TOK_NAME]: `${'$'}{{ ${['sec', 'rets'].join('')}.GITHUB_TOKEN }}` };
    expect(ke.env).toEqual({ BASH_ENV: '', ENV: '', PIPEGEN_COSIGN_KEY: '${{ secrets.PIPEGEN_COSIGN_KEY }}', [PW_NAME]: `${'$'}{{ secrets.${PW_NAME} }}`, ...regTok });
    const kl = lastRun(keyless);
    // keyless: the GitHub OIDC identity of the job, a public transparency-log entry, no key, no secret
    expect(kl.run).toContain('sign --yes --oidc-provider=github-actions "$ref"');
    expect(kl.run).not.toMatch(/--key|tlog-upload|COSIGN_PASSWORD/);
    expect(kl.env).toEqual({ BASH_ENV: '', ENV: '', ...regTok });
    // what renders it: only the reviewed cosign entry; renderStep still refuses cosign (the sign job owns its flags, BP-3)
    expect(() => renderStep(specFor(COSIGN, { needId: 'signing' }), COSIGN, p, { profile: prof })).toThrow(RenderError);
    expect(() => renderSignSteps({ ...COSIGN, id: 'cosign-fork' }, 'key-env', IMG)).toThrow(RenderError);
    expect(() => renderSignSteps({ ...COSIGN, candidate: { ...COSIGN.candidate, reviewed: false } as unknown as ReviewedTool['candidate'] }, 'key-env', IMG)).toThrow(RenderError);
    for (const repo of ['ghcr.io/o/r-app:latest', 'ghcr.io/o/r-app@sha256:' + 'a'.repeat(64), 'quay.io/o/x', "ghcr.io/o/x'y", 'ghcr.io/o/../x', 'ghcr.io/O/x']) {
      expect(() => renderSignSteps(COSIGN, 'key-env', { service: 'app', repo }), repo).toThrow(RenderError);
    }

    // the referee: the sign steps pass in the job sign (key-env in the signing environment), and nowhere else
    const keDraft = signingDraft(KEY_ENV);
    const signJob = (steps: RenderedStep[], over: Job = {}): Job => job([digestDownload(), ...steps], { permissions: SIGN_PERMS, environment: 'pipegen-signing', ...over });
    // (G2-R-sec2: a sign job that writes to the registry is reached only from a deploy caller of pipegen.yml on a default-branch push)
    const keFull = withPipeline(keDraft);
    expect(show(await runWith([signFile({ sign: signJob(keyEnv) }), deployCaller(keFull, './.github/workflows/sign.yml')], keFull))).toBe('');
    for (const id of ['image-publish', 'pipegen-verify', 'deploy', 'base-scan']) {
      const perms = id === 'pipegen-verify' ? VERIFY_PERMS : SIGN_PERMS;
      const r = await runWith([signFile({ [id]: signJob(keyEnv, { permissions: perms, ...(id === 'pipegen-verify' ? {} : { environment: undefined }) }) })], keDraft);
      expect(r.ok, `${id}: ${show(r)}`).toBe(false);
      expect(r.issues.some((i) => /sign step|signs only in the job sign|pipegen-signing/.test(i.message)), `${id}: ${show(r)}`).toBe(true);
    }
    // key-env signs only in the signing environment (its key lives there)
    const noEnv = await runWith([signFile({ sign: signJob(keyEnv, { environment: undefined }) })], keDraft);
    expect(has(noEnv, 'permissions', /environment pipegen-signing/), show(noEnv)).toBe(true);
    // an edited sign step (the transparency-log flag dropped, another key) is not pipegen's: refused
    const edited = keyEnv.map((s) => (s === lastRun(keyEnv) ? { ...s, run: (s.run as string).replace(' --tlog-upload=false', '') } : s));
    expect((await runWith([signFile({ sign: signJob(edited) })], keDraft)).ok).toBe(false);
    // keyless: the same rule; the key-env steps are not this draft's steps
    const klDraft = signingDraft(KEYLESS);
    expect(show(await runWith([signFile({ sign: signJob(keyless, { environment: undefined, permissions: { contents: 'read', [OIDC]: 'write' } }) })], klDraft))).toBe('');
    expect((await runWith([signFile({ sign: signJob(keyEnv) })], klDraft)).ok).toBe(false);
    expect((await runWith([signFile({ 'image-publish': signJob(keyless, { environment: undefined, permissions: SIGN_PERMS }) })], klDraft)).ok).toBe(false);
    // a job with no power (contents: read) and no row of its own: the placement rule alone refuses the sign step there
    const plain = await runWith([signFile({ lint: job([digestDownload(), ...keyless]) })], klDraft);
    expect(has(plain, 'permissions', /signs only in the job sign/), show(plain)).toBe(true);
    // keyless on a private repository would put its image names in a public log: refused, whatever the files
    const priv = await runWith([signFile({ sign: signJob(keyless, { environment: undefined, permissions: { contents: 'read', [OIDC]: 'write' } }) })], { ...klDraft, profile: { ...klDraft.profile, private: true } });
    expect(has(priv, 'permissions', /keyless/), show(priv)).toBe(true);
    // no signing plan: no sign step is pipegen's
    expect((await runWith([signFile({ sign: signJob(keyEnv) })], bare({ capabilities: { ...draftOf().capabilities, environments: true } }))).ok).toBe(false);
    // the signing key's secrets reach only the sign step, never another step of the job
    const leak = { ...digestDownload(), env: { PIPEGEN_COSIGN_KEY: '${{ secrets.PIPEGEN_COSIGN_KEY }}' } };
    const r = await runWith([rawFile({ sign: job([leak, ...keyEnv], { permissions: SIGN_PERMS, environment: 'pipegen-signing' }) }, { on: { workflow_call: null } }, '.github/workflows/sign.yml')], keDraft);
    expect(has(r, 'injection', /signing secret "PIPEGEN_COSIGN_KEY" reaches a step that is not pipegen's sign step/), show(r)).toBe(true);
  });

  it('render: cosign verify with the pub-key sha256 literal checked first; gh attestation verify only from the pinned gh entry; only in pipegen-verify', async () => {
    expect(pubKeySha256(PEM)).toBe(PUB_SHA);
    const keDraft = signingDraft(KEY_ENV);
    const ke = renderVerifySteps(COSIGN, keDraft, IMG);
    const run = lastRun(ke).run as string;
    // (G7: and the job's own token for cosign's registry login, packages: read; a private image's signature answers no one else)
    expect(lastRun(ke).env).toEqual({ BASH_ENV: '', ENV: '', PIPEGEN_COSIGN_PUB: '${{ vars.PIPEGEN_COSIGN_PUB }}', [REG_VAR]: '${{ github.token }}' });
    // the literal pipegen recorded, checked against the variable's exact text BEFORE cosign reads the key, and the checked file is the key used
    expect(run).toContain(`want='${PUB_SHA}'`);
    const check = run.indexOf('if [ "$got" != "$want" ]');
    const verify = run.indexOf(' verify --key "$keydir/cosign.pub" --insecure-ignore-tlog=true -a pipegen.commit="$GITHUB_SHA" "$ref"');
    expect(check).toBeGreaterThan(-1);
    expect(verify).toBeGreaterThan(check);
    expect(run.indexOf('printf \'%s\' "$PIPEGEN_COSIGN_PUB" > "$keydir/cosign.pub"')).toBeLessThan(check);
    expect(run).not.toContain('env://PIPEGEN_COSIGN_PUB');
    // no recorded hash, or not a sha256: nothing to trust the variable against, so no verify step
    for (const sha of [undefined, 'A'.repeat(64), 'a'.repeat(63), "a'"]) {
      const d = signingDraft({ ...KEY_ENV, ...(sha === undefined ? { cosignPubSha256: undefined } : { cosignPubSha256: sha }) });
      expect(() => renderVerifySteps(COSIGN, d, IMG), String(sha)).toThrow(RenderError);
    }
    // keyless: the sign job's exact identity and GitHub's OIDC issuer
    const klDraft = signingDraft(KEYLESS);
    const kl = lastRun(renderVerifySteps(COSIGN, klDraft, IMG)).run as string;
    expect(keylessIdentity(prof)).toBe('https://github.com/o/r/.github/workflows/pipegen.yml@refs/heads/main');
    expect(kl).toContain(`verify --certificate-identity '${keylessIdentity(prof)}' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' --certificate-github-workflow-sha "$GITHUB_SHA" --certificate-github-workflow-trigger push --certificate-github-workflow-repository '${prof.owner}/${prof.repo}' "$ref"`);
    // attest: the reviewed pinned gh release (installed by its sha256), never the runner's gh
    const at = signingDraft(ATTEST);
    const gh = ghEntry();
    const ghSteps = renderVerifySteps(gh, at, IMG);
    expect(ghSteps[0]?.env?.PIPEGEN_DL_URL).toBe('https://github.com/cli/cli/releases/download/v2.103.3/gh_2.103.3_linux_amd64.tar.gz');
    expect(ghSteps[0]?.env?.PIPEGEN_DL_SHA256).toBe('4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d');
    const ghRun = lastRun(ghSteps).run as string;
    // (G3 ruling: the sign workflow is the project's own central file, <project>--sign.yml, since its content is the draft's plan)
    expect(attestSignerWorkflow('o/pipelines', 'r')).toBe('o/pipelines/.github/workflows/r--sign.yml');
    // G2-R-sec 2: bound like keyless: the source is the app's default branch, the signer is the central sign workflow AT the central commit
    // pipegen pinned (a reusable workflow called at a commit signs with that commit), on a GitHub-hosted runner
    // G15a: and the deployed commit itself (--source-digest, the push's GITHUB_SHA, checked as 40 hex first)
    expect(ghRun).toContain(`"$RUNNER_TEMP/pipegen-bin/pipegen-gh-verify/gh" attestation verify "oci://$ref" --repo 'o/r' --source-ref 'refs/heads/main' --source-digest "$GITHUB_SHA" --signer-workflow 'o/pipelines/.github/workflows/r--sign.yml' --signer-digest '${'a'.repeat(40)}' --no-public-good --deny-self-hosted-runners`);
    for (const defaultBranch of ['-x', 'a..b', "ma'in", 'ma in', '']) {
      expect(() => renderVerifySteps(gh, { ...at, profile: { ...at.profile, defaultBranch } }, IMG), defaultBranch).toThrow(RenderError);
    }
    expect(() => renderVerifySteps(gh, { ...at, centralPin: { repo: 'o/pipelines', sha: 'main' } }, IMG)).toThrow(RenderError);
    expect(ghRun).not.toMatch(/(?:^|[\s;|&(])gh\s/m);
    expect(lastRun(ghSteps).env).toEqual({ BASH_ENV: '', ENV: '', [GHT_NAME]: '${{ github.token }}' });
    for (const bad of [ghEntry({ id: 'gh-fork' }), ghEntry({ repo: 'evil/cli' }), ghEntry({ reviewed: false } as unknown as Partial<Candidate>), COSIGN]) {
      expect(() => renderVerifySteps(bad.id === 'gh-fork' ? { ...bad, id: 'gh-fork' } : bad, at, IMG), bad.candidate.repo).toThrow(RenderError);
    }
    expect(() => renderVerifySteps(gh, signingDraft(ATTEST, { centralPin: undefined }), IMG)).toThrow(RenderError);
    // and cosign never verifies an attest-mode image, nor gh a cosign one
    expect(() => renderVerifySteps(gh, keDraft, IMG)).toThrow(RenderError);

    // the referee: only in pipegen-verify (in the signing environment), and for attest only with the gh entry in the reviewed list
    // G7: the verify job's own steps come first (find-run under its id, the head check, the digest of the gated run), then the signature check
    const verifyJob = (steps: RenderedStep[], over: Job = {}): Job => job([...verifyTail(renderFindRunStep(GATE, { central: { repo: 'o/pipelines', sha: 'a'.repeat(40), project: imageProf.repo } })), renderDigestStep('app'), ...steps], { permissions: VERIFY_PERMS, environment: 'pipegen-signing', 'timeout-minutes': VERIFY_LIMIT, ...over });
    const vf = (jobs: Record<string, Job>): CreatedFile => ({ ...workflow(jobs, { on: { workflow_call: null } }), path: '.github/workflows/deploy-verify.yml' });
    expect(show(await runWith([vf({ 'pipegen-verify': verifyJob(ke) })], keDraft))).toBe('');
    for (const id of ['sign', 'deploy', 'image-publish']) {
      const r = await runWith([vf({ [id]: verifyJob(ke, { permissions: id === 'sign' ? SIGN_PERMS : { contents: 'read' }, ...(id === 'sign' ? {} : { environment: undefined }) }) })], keDraft);
      expect(r.ok, `${id}: ${show(r)}`).toBe(false);
      expect(r.issues.some((i) => /verify step|verifies only in the job pipegen-verify|pipegen-signing/.test(i.message)), `${id}: ${show(r)}`).toBe(true);
    }
    // the hash check moved after the verify: not pipegen's step
    const swapped = (() => {
      const lines = run.split('\n');
      const v = lines.findIndex((l) => l.includes(' verify --key '));
      const c = lines.findIndex((l) => l.includes('if [ "$got" != "$want" ]'));
      const out = [...lines];
      [out[v], out[c]] = [out[c] as string, out[v] as string];
      return ke.map((s) => (s === lastRun(ke) ? { ...s, run: out.join('\n') } : s));
    })();
    expect((await runWith([vf({ 'pipegen-verify': verifyJob(swapped) })], keDraft)).ok).toBe(false);
    // another literal (a key the attacker controls, with its own hash) is not this draft's step
    const otherKey = renderVerifySteps(COSIGN, signingDraft({ ...KEY_ENV, cosignPubSha256: 'b'.repeat(64) }), IMG);
    expect((await runWith([vf({ 'pipegen-verify': verifyJob(otherKey) })], keDraft)).ok).toBe(false);
    // the variable only on the verify step: the same env on another run step is an expression pipegen does not write
    const leaked = { ...digestDownload() };
    const pubOnOther: RenderedStep = { id: 'pipegen-verify-0000000000000000', name: 'x', run: 'echo "$PIPEGEN_COSIGN_PUB"', shell: 'bash', env: { PIPEGEN_COSIGN_PUB: '${{ vars.PIPEGEN_COSIGN_PUB }}' } };
    expect((await runWith([rawFile({ 'pipegen-verify': job([leaked, pubOnOther], { permissions: VERIFY_PERMS, environment: 'pipegen-signing' }) }, { on: { workflow_call: null } }, '.github/workflows/deploy-verify.yml')], keDraft)).ok).toBe(false);
    // attest: with the real gh entry the step is pipegen's own verify step (recognised by content, in pipegen-verify); without the entry
    // nothing renders it, so it is refused. G15a-R0b: attest verify is on; its job's egress step reaches gh's attestation hosts (the
    // referee requires them there, test/g15-attest-verify.test.ts), and with them the job passes
    const atJob = verifyJob(ghSteps);
    const atEgress = { ...atJob, steps: [renderEgressStep(['ghcr', 'github-releases', GITHUB_ATTEST_SET], { dockerNetworks: false }), ...(atJob.steps as RenderedStep[]).slice(1)] };
    const atFile = vf({ 'pipegen-verify': atEgress });
    const withGh = await runWith([atFile], at, reviewedList());
    expect(show(withGh)).toBe('');
    // without them (the default egress step of these tests) it is refused
    expect(has(await runWith([vf({ 'pipegen-verify': atJob })], at, reviewedList()), 'template', /attestation hosts/)).toBe(true);
    const noGh = await runWith([atFile], at, reviewedList().filter((t) => t.id !== GH_ID));
    expect(noGh.ok).toBe(false);
    expect(noGh.notes.some((n) => /gh/.test(n)), noGh.notes.join('\n')).toBe(true);
  });
});

// ---------- the image hand-off (B6) ----------

const app = service({ name: 'app', path: '.', dockerfile: 'Dockerfile', port: 3000 });
const imgProf = { ...prof, services: [app] };
const BUILD_PUSH = entry('docker-build-push-action');
const TRIVY = entry('trivy-image');
const buildSpec = (svc = 'app', choices: StepSpec['choices'] = {}): StepSpec => specFor(BUILD_PUSH, { needId: 'image-build', service: svc, choices });
const scanSpec = (choices: StepSpec['choices'] = {}): StepSpec => specFor(TRIVY, { needId: 'image-scan', service: 'app', choices });
const imageDraft = (over: Partial<PipelineDraft> = {}): PipelineDraft => draftOf({
  profile: imgProf, needs: [needOf('image-build', 'app'), needOf('image-scan', 'app')], steps: [buildSpec(), scanSpec()], ...over,
});
const ictx = (d: PipelineDraft = imageDraft()): RenderContext => ({ profile: d.profile });
/** The image-build job: checkout, the build (no push), the archive and its upload. */
const buildJob = (d: PipelineDraft = imageDraft(), over: Job = {}, edit?: (s: RenderedStep[]) => RenderedStep[]): Job => {
  const b = renderImageBuild(buildSpec(), BUILD_PUSH, p, ictx(d));
  const steps = [...renderJobPrelude({}, p).steps, ...b.steps];
  return job(edit === undefined ? steps : edit(steps), { outputs: b.outputs, ...over });
};
/** The scan job of the archive: download, hash check, trivy --input, scrub, upload. */
const scanJob = (d: PipelineDraft = imageDraft(), over: Job = {}, edit?: (s: RenderedStep[]) => RenderedStep[]): Job => {
  const r = renderImageArchiveScan(scanSpec(), TRIVY, p, ictx(d));
  const raw = r.output?.path as string;
  const artifact = 'pipegen-out-image-scan--app';
  const steps = [...r.steps, renderScrub(artifact, raw, 'trivy-image', 'sarif', GATE), renderUpload(artifact, scrubbedPath(raw), p)];
  const all = edit === undefined ? steps : edit(steps);
  return job(all, { needs: [imageBuildJobId('app')], outputs: jobOutputsFor(all), ...over });
};
const imageFile = (jobs: Record<string, Job>): CreatedFile => workflow(jobs);

/** The deploy layout of pipegen.yml (ruling B2): the honest gate pipeline, a default-only push, the review trigger; deploy jobs need the gate. */
const pubDraft = draftOf({ profile: { ...prof, services: prof.services.map((s) => (s.name === 'app' ? { ...s, dockerfile: 'Dockerfile' } : s)) } });
const DEPLOY_ON = { push: defaultPushTrigger('main'), pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
const deployFile = (extra: Record<string, Job>, on: unknown = DEPLOY_ON, path = CALLER_WORKFLOW): CreatedFile => ({ ...workflow({ ...jobsOf(pubDraft), ...extra }, { on }), path });
/**
 * Carry G5→G7 1 (G7): a public repository signs keyless (the referee re-derives the mode, never trusts a missing plan), so a deploy file that
 * publishes an image holds the keyless sign job of its plan too: an unsigned publish from a public repository must never ship.
 */
const signedDraft = { ...pubDraft, signing: KEYLESS };
/** G15a-R10 r4-2, r4-3: the published image's tag (the renderer's helper) and the digest hand-off image-publish ends with (releaseJobs' form). */
const PUB_TAG = `${publishedImageRepo(pubDraft.profile.owner, pubDraft.profile.repo, 'app')}:${PUBLISH_TAG}`;
const publishTail = (): RenderedStep[] => {
  const name = imageDigestArtifact('app');
  return [renderPublishDigestStep('app', publishedImageRepo(pubDraft.profile.owner, pubDraft.profile.repo, 'app')), { ...renderPlatformStep('upload-artifact', p, { name, path: `\${{ runner.temp }}/pipegen-out/${name}` }), name: 'Upload the image digest of app' }];
};
const keylessSign = (): Job => job([digestDownload(), ...renderSignSteps(COSIGN, 'keyless', IMG)], { permissions: { contents: 'read', [OIDC]: 'write', packages: 'write' }, if: DEPLOY_PUSH_IF, needs: ['gate', 'image-publish'] });

describe('G2: the image hand-off (B6)', () => {
  it('render: image-build uploads an OCI archive and its sha256; the scan job checks the hash before trivy --input', async () => {
    expect(imageBuildJobId('app')).toBe(jobIdFor('image-build', 'app'));
    const b = renderImageBuild(buildSpec(), BUILD_PUSH, p, ictx());
    const [build, archive, upload] = b.steps as [RenderedStep, RenderedStep, RenderedStep];
    // the build: the reviewed build-push action, never pushing, with the service's own Dockerfile and a local tag
    expect(build.uses).toBe(BUILD_PUSH.step.action?.uses);
    expect(build.with).toMatchObject({ push: 'false', context: '.', file: 'Dockerfile', tags: imageBuildTag('app'), 'no-cache': 'true' });
    // the archive of exactly that image, and its sha256 as the job output
    expect(archive.id).toBe(IMAGE_ARCHIVE_STEP_ID);
    expect(archive.run).toContain(`/usr/bin/docker image save --output "$dir/image.tar" '${imageBuildTag('app')}'`);
    expect(archive.run).toContain('echo "sha256=$sum" >> "$GITHUB_OUTPUT"');
    expect(b.outputs).toEqual({ [IMAGE_SHA_OUTPUT]: `\${{ steps.${IMAGE_ARCHIVE_STEP_ID}.outputs.sha256 }}` });
    expect(upload.with).toMatchObject({ name: imageArchiveArtifact('app'), path: `\${{ runner.temp }}/pipegen-out/${imageArchiveArtifact('app')}` });
    expect(imageArchiveArtifact('app')).toBe('pipegen-out-image-archive--app');
    // a push or a sub-folder service is never an image-build
    expect(() => renderImageBuild(buildSpec('app', { push: 'true' }), BUILD_PUSH, p, ictx())).toThrow(RenderError);
    const web = service({ name: 'web', path: 'apps/web', dockerfile: 'apps/web/Dockerfile' });
    expect(() => renderImageBuild(buildSpec('web'), BUILD_PUSH, p, { profile: { ...imgProf, services: [app, web] } })).toThrow(RenderError);

    const s = renderImageArchiveScan(scanSpec(), TRIVY, p, ictx());
    const ids = s.steps.map((x) => x.id ?? x.uses?.split('@')[0]);
    const check = s.steps.findIndex((x) => x.id === 'pipegen-image-check--app');
    const scan = s.steps.findIndex((x) => x.run?.includes('"$bin/trivy" image') === true);
    expect(s.steps[0]?.uses?.startsWith('actions/download-artifact@'), JSON.stringify(ids)).toBe(true);
    expect(check).toBeGreaterThan(0);
    expect(scan).toBeGreaterThan(check);
    const checkStep = s.steps[check] as RenderedStep;
    expect(checkStep.env).toEqual({ BASH_ENV: '', ENV: '', PIPEGEN_IMAGE_SHA256: '${{ needs.image-build--app.outputs.image-sha256 }}' });
    expect(checkStep.run).toContain('sha256sum --check --strict');
    const scanRun = (s.steps[scan] as RenderedStep).run as string;
    expect(scanRun).toContain('image --config "$cfg/trivy.yaml" --disable-telemetry --skip-version-check --skip-check-update --format sarif --output trivy-image.sarif --exit-code 10 --input "$RUNNER_TEMP/pipegen-out/pipegen-out-image-archive--app/image.tar" --severity');
    expect(scanRun).not.toContain('ghcr.io');
    expect(Object.values((s.steps[scan] as RenderedStep).env ?? {})).not.toContain(expect.stringContaining('@sha256:'));
    // syft reads the same archive
    const syft = entry('syft');
    const sb = renderImageArchiveScan(specFor(syft, { needId: 'sbom', service: 'app' }), syft, p, ictx());
    expect(lastRun(sb.steps).run).toContain('"docker-archive:$RUNNER_TEMP/pipegen-out/pipegen-out-image-archive--app/image.tar"');

    // the referee: the build job and the scan job pass as rendered
    const d = imageDraft();
    expect(show(await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d) })], d))).toBe('');
    // the scan before its hash check, or with no check: refused
    const noCheck = await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d, {}, (x) => x.filter((y) => y.id !== 'pipegen-image-check--app')) })], d);
    expect(noCheck.ok, show(noCheck)).toBe(false);
    const late = await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d, {}, (x) => { const c = x.find((y) => y.id === 'pipegen-image-check--app') as RenderedStep; const rest = x.filter((y) => y !== c); rest.splice(rest.length - 2, 0, c); return rest; }) })], d);
    expect(late.ok, show(late)).toBe(false);
    // the hash check reading another job's output, or a job that does not need the build
    const otherSha = await runWith([rawFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d, {}, (x) => x.map((y) => (y.id === 'pipegen-image-check--app' ? { ...y, env: { ...y.env, PIPEGEN_IMAGE_SHA256: '${{ needs.other.outputs.image-sha256 }}' } } : y))) })], d);
    expect(otherSha.ok, show(otherSha)).toBe(false);
    const noNeeds = await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d, { needs: [] }) })], d);
    expect(noNeeds.ok, show(noNeeds)).toBe(false);
    // the build job: the archive and its upload come right after the build and nothing else follows; the output only from the archive step
    const extra = await runWith([imageFile({ 'image-build--app': buildJob(d, {}, (x) => [...x, { ...(x.at(-1) as RenderedStep), with: { ...(x.at(-1) as RenderedStep).with } }]) })], d);
    expect(extra.ok, show(extra)).toBe(false);
    const noArchive = await runWith([imageFile({ 'image-build--app': buildJob(d, { outputs: undefined }, (x) => x.filter((y) => y.id !== IMAGE_ARCHIVE_STEP_ID)) })], d);
    expect(noArchive.ok, show(noArchive)).toBe(false);
    const elsewhere = await runWith([imageFile({ 'image-build--app': buildJob(d), 'lint--app': job(renderJobPrelude({}, p).steps, { outputs: { [IMAGE_SHA_OUTPUT]: `\${{ steps.${IMAGE_ARCHIVE_STEP_ID}.outputs.sha256 }}` } }) })], d);
    expect(has(elsewhere, 'injection', /image-sha256/), show(elsewhere)).toBe(true);
    // G2-R-sec 1: the tail is exempt only after harmless steps and the build: repo code before it puts the archive and upload under the order rule
    const repoStep: RenderedStep = { id: 'x-repo', name: 'repo code', run: 'npm ci\n', shell: 'bash' };
    const steps0 = (buildJob(d).steps as RenderedStep[]);
    expect(checkJobOrder(steps0, { id: 'image-build--app', scans: NO_SCANS })).toEqual([]);
    const withRepo = [...steps0.slice(0, 1), repoStep, ...steps0.slice(1)];
    expect(checkJobOrder(withRepo, { id: 'image-build--app', scans: NO_SCANS }).join('\n')).toMatch(/comes after the repo-code step "repo code"/);
    const injected = await runWith([rawFile({ 'image-build--app': buildJob(d, {}, (x) => [...x.slice(0, 1), repoStep, ...x.slice(1)]) })], d);
    expect(has(injected, 'injection', /comes after the repo-code step/), show(injected)).toBe(true);
    // the archive step of another service's job, or in a job that is not an image build
    const moved = await runWith([imageFile({ 'image-scan--app': scanJob(d, {}, (x) => [...renderImageBuild(buildSpec(), BUILD_PUSH, p, ictx(d)).steps.filter((y) => y.id === IMAGE_ARCHIVE_STEP_ID), ...x]) })], d);
    expect(moved.ok, show(moved)).toBe(false);
  });

  it('referee: an image base twin whose input equals the head\'s → refused', async () => {
    const X = `ghcr.io/o/r-app@sha256:${'1'.repeat(64)}`;
    const Y = `ghcr.io/o/r-app@sha256:${'2'.repeat(64)}`;
    const d = draftOf({ profile: imgProf, needs: [needOf('image-scan', 'app')], steps: [scanSpec()] });
    const head = (image: string): Job => {
      const b = renderFindingsBlock(scanSpec(), TRIVY, p, { profile: imgProf, targets: { image } }, GATE);
      return job(b.steps, { outputs: jobOutputsFor(b.steps) });
    };
    const base = (image: string): Job => {
      const b = renderFindingsBlock(scanSpec(), TRIVY, p, { profile: imgProf, targets: { image }, base: true }, GATE);
      const steps = [...renderJobPrelude({ baseRef: true }, p).steps, ...b.steps];
      return job(steps, { outputs: jobOutputsFor(steps), permissions: { contents: 'read', actions: 'read' } });
    };
    // control: a base twin of another image (built from the base commit) is judged by shape as before
    const ok = await runWith([workflow({ 'image-scan--app': head(X), 'base-scan': base(Y) })], d);
    expect(ok.issues.some((i) => /base twin/.test(i.message)), show(ok)).toBe(false);
    // the same image on both sides: every head finding would look old (a wrong pass), so it is refused
    const same = await runWith([workflow({ 'image-scan--app': head(X), 'base-scan': base(X) })], d);
    expect(has(same, 'not-gate-readable', /base twin/), show(same)).toBe(true);
    // the same, with the twin in another file of the same pipeline
    const split = await runWith([workflow({ 'image-scan--app': head(X) }), { ...workflow({ 'base-scan': base(X) }), path: '.github/workflows/pipegen-merge.yml' }], d);
    expect(has(split, 'not-gate-readable', /base twin/), show(split)).toBe(true);
    // G2-R-sec 3: compared on the parsed reference and the digest, not the text: another spelling of the same image, or another name with
    // the same digest, is the same input
    const D1 = `sha256:${'1'.repeat(64)}`;
    for (const [h, b] of [[`docker.io/library/nginx@${D1}`, `nginx@${D1}`], [`nginx@${D1}`, `index.docker.io/library/nginx@${D1}`], [`library/nginx@${D1}`, `docker.io/library/nginx@${D1}`], [X, `ghcr.io/o/other@${D1}`], [X, `docker.io/library/nginx@${D1}`]] as const) {
      const r = await runWith([workflow({ 'image-scan--app': head(h), 'base-scan': base(b) })], d);
      expect(has(r, 'not-gate-readable', /base twin/), `${h} / ${b}: ${show(r)}`).toBe(true);
    }
    // a tag with the digest, or upper case: not a form pipegen writes, so the twin is no step of pipegen's at all
    for (const b of [`ghcr.io/o/r-app:v1@${D1}`, `GHCR.IO/o/r-app@${D1}`, `ghcr.io/O/r-app@${D1}`]) {
      const planted = base(Y);
      const edited = { ...planted, steps: (planted.steps as RenderedStep[]).map((st) => (st.env === undefined ? st : { ...st, env: Object.fromEntries(Object.entries(st.env).map(([k, v]) => [k, v === Y ? b : v])) })) };
      const r = await runWith([rawFile({ 'image-scan--app': head(X), 'base-scan': edited })], d);
      expect(r.ok, `${b}: ${show(r)}`).toBe(false);
    }
    // a base twin with no head step of its check, or next to a head that reads the PR's image archive: nothing to compare, refused
    const alone = await runWith([workflow({ 'base-scan': base(Y) })], d);
    expect(has(alone, 'not-gate-readable', /base twin/), show(alone)).toBe(true);
    const ad0 = imageDraft();
    const withArchive = await runWith([imageFile({ 'image-build--app': buildJob(ad0), 'image-scan--app': scanJob(ad0), 'base-scan': base(Y) })], ad0);
    // (G2-R1 I2: with the image build in the draft no base twin of that scan is pipegen's step at all)
    expect(has(withArchive, 'unreviewed', /not a step pipegen renders/), show(withArchive)).toBe(true);
    // the archive scan has no base twin at all (there is no base build yet, B6): its steps in base-scan are not pipegen's
    const ad = imageDraft();
    const archiveSteps = renderImageArchiveScan(scanSpec(), TRIVY, p, ictx(ad)).steps;
    const twin = await runWith([imageFile({ 'image-build--app': buildJob(ad), 'base-scan': job([...renderJobPrelude({ baseRef: true }, p).steps, ...archiveSteps], { needs: [imageBuildJobId('app')], permissions: { contents: 'read', actions: 'read' } }) })], ad);
    expect(twin.ok, show(twin)).toBe(false);
  });

  it('referee: build-push bound to its service\'s build context and Dockerfile', async () => {
    const worker = service({ name: 'worker', path: '.', dockerfile: 'worker.Dockerfile', port: 3001 });
    const two = { ...prof, services: [app, worker] };
    const d = draftOf({ profile: two, needs: [needOf('image-build', 'app'), needOf('image-build', 'worker')], steps: [buildSpec('app'), buildSpec('worker')] });
    const own = (svc: string): Job => {
      const b = renderImageBuild(buildSpec(svc), BUILD_PUSH, p, { profile: two });
      return job([...renderJobPrelude({}, p).steps, ...b.steps], { outputs: b.outputs });
    };
    expect(show(await runWith([imageFile({ 'image-build--app': own('app'), 'image-build--worker': own('worker') })], d))).toBe('');
    const swap = (j: Job, w: Record<string, string>): Job => ({ ...j, steps: (j.steps as RenderedStep[]).map((s) => (s.uses?.startsWith('docker/build-push-action@') === true ? { ...s, with: { ...s.with, ...w } } : s)) });
    // another service's Dockerfile in this service's job
    const other = await runWith([imageFile({ 'image-build--app': swap(own('app'), { file: 'worker.Dockerfile' }) })], d);
    expect(has(other, 'template', /Dockerfile of the service/), show(other)).toBe(true);
    // a file that is no service's Dockerfile, or none at all
    for (const w of [{ file: 'evil/Dockerfile' }, { file: '' }]) {
      const r = await runWith([imageFile({ 'image-build--app': swap(own('app'), w) })], d);
      expect(r.ok, `${JSON.stringify(w)}: ${show(r)}`).toBe(false);
    }
    const nofile = own('app');
    const without = await runWith([imageFile({ 'image-build--app': { ...nofile, steps: (nofile.steps as RenderedStep[]).map((s) => (s.uses?.startsWith('docker/build-push-action@') === true ? { ...s, with: Object.fromEntries(Object.entries(s.with ?? {}).filter(([k]) => k !== 'file')) } : s)) } })], d);
    expect(has(without, 'template', /Dockerfile of the service/), show(without)).toBe(true);
    // a push from an image-build job, another tag than the one the archive saves
    const push = await runWith([imageFile({ 'image-build--app': swap(own('app'), { push: 'true' }) })], d);
    expect(has(push, 'template', /push/), show(push)).toBe(true);
    const tag = await runWith([imageFile({ 'image-build--app': swap(own('app'), { tags: 'ghcr.io/o/other:x' }) })], d);
    expect(tag.ok, show(tag)).toBe(false);
    // a job of no service, or a service in a sub-folder (the context is the repository root, ruling S8)
    const nobody = await runWith([imageFile({ 'image-build--ghost': own('app') })], d);
    expect(nobody.ok, show(nobody)).toBe(false);
    const web = service({ name: 'web', path: 'apps/web', dockerfile: 'apps/web/Dockerfile' });
    const wd = draftOf({ profile: { ...prof, services: [app, web] }, needs: [needOf('image-build', 'web')], steps: [buildSpec('web')] });
    const webJob = swap(own('app'), { file: 'apps/web/Dockerfile', tags: imageBuildTag('web') });
    const sub = await runWith([imageFile({ 'image-build--web': webJob })], wd);
    expect(has(sub, 'template', /sub-folder|build context/), show(sub)).toBe(true);
    // build-push in a job that is neither an image build nor image-publish
    const lint = await runWith([imageFile({ 'lint--app': { ...own('app'), outputs: undefined } })], d);
    expect(has(lint, 'template', /build-push/), show(lint)).toBe(true);
    // image-publish: a Dockerfile of a service only
    // (G15a-R10 r4-2, r4-3: the plan's tag, and the digest hand-off after the push)
    const pub = (w: Record<string, string>): Job => job([...renderJobPrelude({}, p).steps, { id: BUILD_PUSH_STEP_ID, ...renderPlatformStep('build-push', p, { file: 'Dockerfile', tags: PUB_TAG }, { push: 'true' }), with: { ...renderPlatformStep('build-push', p, { file: 'Dockerfile', tags: PUB_TAG }, { push: 'true' }).with, ...w } }, ...publishTail()], { permissions: { contents: 'read', packages: 'write' } });
    // (G2-R1 I3: image-publish pushes only from a deploy job of pipegen.yml on a default-branch push, so it is judged there)
    const dep = (w: Record<string, string>): Job => ({ ...pub(w), if: DEPLOY_PUSH_IF, needs: ['gate'] });
    expect(show(await runWith([deployFile({ 'image-publish': dep({}), sign: keylessSign() })], signedDraft))).toBe('');
    expect(has(await runWith([deployFile({ 'image-publish': dep({ file: 'evil/Dockerfile' }) })], pubDraft), 'template', /Dockerfile of a service/)).toBe(true);
  });
});

describe('G2: the exact forms one by one (the emitter and the shared rules)', () => {
  it('forms: each expression only on the step id it belongs to; image-sha256 only on an image build; the archive tail exact', async () => {
    const run = (id: string, env: Record<string, string>): RenderedStep => ({ id, name: 'x', run: 'true\n', shell: 'bash', env });
    const signId = lastRun(renderSignSteps(COSIGN, 'key-env', IMG)).id as string;
    const verifyId = lastRun(renderVerifySteps(COSIGN, signingDraft(KEY_ENV), IMG)).id as string;
    expect(() => checkExpressions(run(signId, { ...SIGN_STEP_ENV }))).not.toThrow();
    expect(() => checkExpressions(run(verifyId, { ...SIGN_STEP_ENV }))).toThrow(RenderError);
    expect(() => checkExpressions(run('tool-run-0000000000000000', { ...SIGN_STEP_ENV }))).toThrow(RenderError);
    expect(() => checkExpressions(run(verifyId, { ...VERIFY_STEP_ENV }))).not.toThrow();
    expect(() => checkExpressions(run(signId, { ...VERIFY_STEP_ENV }))).toThrow(RenderError);
    expect(() => checkExpressions(run('pipegen-image-check--app', { PIPEGEN_IMAGE_SHA256: '${{ needs.image-build--app.outputs.image-sha256 }}' }))).not.toThrow();
    for (const v of ['${{ needs.image-build--web.outputs.image-sha256 }}', '${{ needs.other.outputs.image-sha256 }}', '${{ github.event.head_commit.message }}']) {
      expect(() => checkExpressions(run('pipegen-image-check--app', { PIPEGEN_IMAGE_SHA256: v })), v).toThrow(RenderError);
    }
    const archive = (renderImageBuild(buildSpec(), BUILD_PUSH, p, ictx()).steps)[1] as RenderedStep;
    const form = `\${{ steps.${IMAGE_ARCHIVE_STEP_ID}.outputs.sha256 }}`;
    expect(jobOutputsProblems('image-build--app', { [IMAGE_SHA_OUTPUT]: form }, [archive])).toEqual([]);
    expect(jobOutputsProblems('lint--app', { [IMAGE_SHA_OUTPUT]: form }, [archive]).join('\n')).toMatch(/only an image-build--<service> job/);
    // the tail: exactly archive then this service's upload, last, right after the build
    const steps = buildJob().steps as RenderedStep[];
    const ctxJ = { id: 'image-build--app', scans: NO_SCANS };
    expect(checkJobOrder(steps, ctxJ)).toEqual([]);
    expect(checkJobOrder([...steps, steps.at(-1) as RenderedStep], ctxJ).length).toBeGreaterThan(0);
    const otherUpload = { ...(steps.at(-1) as RenderedStep), with: { ...(steps.at(-1) as RenderedStep).with, name: 'pipegen-out-image-archive--web', path: '${{ runner.temp }}/pipegen-out/pipegen-out-image-archive--web' } };
    expect(checkJobOrder([...steps.slice(0, -1), otherUpload], ctxJ).length).toBeGreaterThan(0);
    expect(checkJobOrder(steps, { id: 'image-build--web', scans: NO_SCANS }).length).toBeGreaterThan(0);
    // the archive step in a plain job of no power: only the placement rule refuses it
    const d = imageDraft();
    const plain = await runWith([imageFile({ 'lint--app': job([...renderJobPrelude({}, p).steps, archive]) })], d);
    expect(has(plain, 'permissions', /is made only in its own job/), show(plain)).toBe(true);
    // an image build of no service
    const ghost = await runWith([imageFile({ 'image-build--ghost': buildJob(d) })], d);
    expect(has(ghost, 'template', /image build of no service/), show(ghost)).toBe(true);
    // an archive scan has no base twin
    expect(() => renderImageArchiveScan(scanSpec(), TRIVY, p, { ...ictx(), base: true })).toThrow(/no base twin/);
  });
});

describe('G2: created paths and the vault (S14, CF-1, D-m4)', () => {
  it('referee: created paths outside [A-Za-z0-9._/-] refused', async () => {
    const d = draftOf();
    const good = workflow({});
    for (const ch of ['%', '?', '#', ' ', '+', '~', ':', '@', '!', '*', '&', '=', ',', ';', '\'', '"', '$', '`', '(', '[', '{', 'é', '\u00a0', '\u200b', '\t']) {
      const path = `.github/workflows/a${ch}b.yml`;
      expect(createdPathProblem(path), JSON.stringify(ch)).not.toBeNull();
      const r = await runWith([{ ...good, path }], d);
      expect(has(r, 'template', /The file path is refused/), `${JSON.stringify(ch)}: ${show(r)}`).toBe(true);
    }
    // encoded separators, a leading space, a leading dash: never decoded, never written
    for (const path of ['.github%2Fworkflows%2Fx.yml', ' .github/workflows/x.yml', 'docs/%2e%2e/x', '-x/Dockerfile', 'a/-b']) {
      const r = await runWith([{ ...good, path, part: 'docs' }], d);
      expect(has(r, 'template', /The file path is refused/), `${path}: ${show(r)}`).toBe(true);
    }
    for (const ok of ['.github/workflows/pipegen.yml', 'a_b/c-d/e.f.g', 'Dockerfile']) expect(createdPathProblem(ok), ok).toBeNull();
  });

  it('referee: containsKnownValue derived from deps.vault when absent', async () => {
    // G9 (B7): PIPEGEN.md is the file pipegenDoc builds from the draft's doc data; the referee builds it again
    const d: PipelineDraft = { ...bare(), doc: { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 0, includedMinutes: null }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] } };
    const built = pipegenDoc(d, reviewedList());
    const DOC = built.content;
    const doc: CreatedFile = built;
    const inputs = { pipegenDoc: { baseSha: null, recordSha: null } };
    // no vault and no check: refused (a missing input never reads as "nothing there")
    const none = await runWith([doc], d, reviewedList(), { createdInputs: inputs });
    expect(has(none, 'template', /vault\) was not given/), show(none)).toBe(true);
    // the vault alone is enough: the referee hands its check to the judge
    const calls: string[] = [];
    const vault: KnownValueCheck = { containsKnownValue: (t) => { calls.push(t); return false; }, scrubber: () => (t) => t };
    const viaVault = await runWith([doc], d, reviewedList(), { createdInputs: inputs, vault });
    expect(show(viaVault)).toBe('');
    expect(calls.filter((t) => t === DOC).length, 'the judge asked the vault too').toBeGreaterThanOrEqual(2);
    // the derived check is the vault's: a text the vault holds is refused by the judge (here the vault answers yes only from its second look)
    let seen = 0;
    const late: KnownValueCheck = { containsKnownValue: (t) => (t === DOC ? ++seen > 1 : false), scrubber: () => (t) => t };
    const caught = await runWith([doc], d, reviewedList(), { createdInputs: inputs, vault: late });
    expect(has(caught, 'template', /secret value the user typed/), show(caught)).toBe(true);
    // a check given explicitly still wins (both vault inputs agree by construction)
    const explicit: string[] = [];
    await runWith([doc], d, reviewedList(), { createdInputs: { ...inputs, containsKnownValue: (t) => { explicit.push(t); return false; } }, vault });
    expect(explicit).toContain(DOC);
  });
});

describe('G2: no narrowing value for a blocking need (F2-R11)', () => {
  it('render: no code path renders severity CRITICAL alone, ignore-unfixed true or push true for a blocking need', async () => {
    const list = reviewedList();
    // the data: every narrowing-named choice of every entry has a wide first (default) value
    for (const t of list) {
      for (const [name, values] of Object.entries(t.choices)) {
        const narrows = NARROWING_CHOICES[name];
        if (narrows === undefined) continue;
        expect(narrows(values[0] as string), `${t.id}.${name} default ${values[0]}`).toBe(false);
      }
    }
    expect(entry('trivy-image').choices.severity?.[0]).toBe('HIGH,CRITICAL');
    expect(entry('trivy-config').choices.severity?.[0]).toBe('HIGH,CRITICAL');
    expect(entry('trivy-image').choices['ignore-unfixed']?.[0]).toBe('false');
    expect(BUILD_PUSH.choices.push?.[0]).toBe('false');
    // the default render of the image and IaC scans is the wide one
    const img = lastRun(renderStep(scanSpec(), TRIVY, p, { profile: imgProf, targets: { image: `ghcr.io/o/r@sha256:${'a'.repeat(64)}` } }).steps);
    expect(Object.values(img.env ?? {})).toContain('HIGH,CRITICAL');
    expect(Object.values(img.env ?? {})).not.toContain('CRITICAL');
    // every narrowing value of every entry, for a blocking need (or no word on blocking): refused on every render path
    const ctxs: RenderContext[] = [{ profile: imgProf, targets: { image: `ghcr.io/o/r@sha256:${'a'.repeat(64)}`, k8sDir: '.' } }, { profile: imgProf, targets: { image: `ghcr.io/o/r@sha256:${'a'.repeat(64)}`, k8sDir: '.' }, blocking: true }];
    let narrowed = 0;
    for (const t of list) {
      for (const [name, values] of Object.entries(t.choices)) {
        const narrows = NARROWING_CHOICES[name];
        for (const v of values) {
          if (narrows === undefined || !narrows(v)) continue;
          narrowed++;
          const needId = t.id === 'docker-build-push-action' ? 'image-build' : t.categories.find((c) => c !== 'platform') ?? 'sast';
          const spec = specFor(t, { needId, service: 'app', choices: { [name]: v } });
          for (const c of ctxs) expect(() => renderStep(spec, t, p, c), `${t.id}.${name}=${v}`).toThrow(/narrow/);
          // a non-blocking need may (it can not hide a finding the gate blocks on)
          if (t.id !== 'docker-build-push-action') expect(() => renderStep(spec, t, p, { ...(ctxs[0] as RenderContext), blocking: false }), `${t.id}.${name}=${v}`).not.toThrow();
          if (t.id === 'trivy-image') expect(() => renderImageArchiveScan(spec, t, p, ictx())).toThrow(/narrow/);
          if (t.id === 'docker-build-push-action') expect(() => renderImageBuild(spec, t, p, ictx())).toThrow(RenderError);
        }
      }
    }
    expect(narrowed).toBeGreaterThanOrEqual(4);
    // a list whose first (default) value narrows: refused with no choice given, for a blocking need
    const oldOrder = { ...TRIVY, choices: { ...TRIVY.choices, severity: ['CRITICAL', 'HIGH,CRITICAL'] } };
    expect(() => renderStep(scanSpec(), oldOrder, p, ctxs[0] as RenderContext)).toThrow(/narrow/);
    expect(() => renderStep(scanSpec(), oldOrder, p, { ...(ctxs[0] as RenderContext), blocking: false })).not.toThrow();   // trivy-image CRITICAL and ignore-unfixed true, trivy-config CRITICAL, build-push push true
    // the referee: a file holding a narrowed scan for a blocking need is not pipegen's step, and a blocking action spec with one is refused
    const d = draftOf({ profile: imgProf, needs: [needOf('iac')], steps: [specFor(entry('trivy-config'), { needId: 'iac', choices: { severity: 'CRITICAL' } })] });
    const narrowSteps = renderStep(d.steps[0] as StepSpec, entry('trivy-config'), p, { profile: imgProf, blocking: false }).steps;
    const r = await runWith([workflow({ iac: job([...renderJobPrelude({}, p).steps, ...narrowSteps]) })], d);
    expect(r.ok, show(r)).toBe(false);
    expect(r.notes.some((n) => /narrow a blocking check/.test(n)), r.notes.join('\n')).toBe(true);
    expect(has(r, 'unreviewed', /not a step pipegen renders/), show(r)).toBe(true);
    const push = await runWith([], draftOf({ profile: imgProf, needs: [needOf('image-build', 'app')], steps: [buildSpec('app', { push: 'true' })] }));
    expect(has(push, 'unreviewed', /narrow/), show(push)).toBe(true);
    // a non-blocking need's action spec may push (image-publish's own job is judged by its binding)
    const nb = await runWith([], draftOf({ profile: imgProf, needs: [needOf('image-build', 'app', false)], steps: [buildSpec('app', { push: 'true' })] }));
    expect(nb.issues.some((i) => /narrow/.test(i.message)), show(nb)).toBe(false);
  });

  it('coverage: coverage-py fail-under is code-filled, never the AI\'s', () => {
    expect(CODE_FILLED_CHOICES['coverage-py']).toBe('fail-under');
    const cov = entry('coverage-py');
    expect(aiChoiceNames('coverage-py', cov.choices)).not.toContain('fail-under');
    // even when the entry lists values that are not exactly the coverage minimums, code fills it
    // (proofs 1: a full run offers only proven entries, ruling B8)
    const odd = reviewedList().map((t) => ({ ...t, proofs: 1, ...(t.id === 'coverage-py' ? { choices: { 'fail-under': ['60', '75'] } } : {}) }));
    const py: Service = service({ name: 'api', path: '.', language: 'python', packageManager: 'pip' });
    const need: Need = { id: 'coverage', layer: 'merge', category: 'coverage', service: 'api', why: 't', blocking: true, floor: false };
    const candidates = new Map([['coverage--api', [odd.find((t) => t.id === 'coverage-py')?.candidate as Candidate]]]);
    const offer = builderOffers([need], candidates, profile([py]), { reviewed: odd, bar: {} as never, now: new Date('2026-11-05'), caps: draftOf().capabilities }).offers.get('coverage--api')?.find((o) => o.entry.id === 'coverage-py');
    expect(offer?.aiChoices).toEqual({});
    expect(offer?.codeChoices).toEqual({ 'fail-under': '60' });
  });
});

describe('G2 fix round 1 (ruling G2-R1)', () => {
  it('referee: a non-blocking copy of a need on another layer never lets a narrowing value through (G2-R1 I1)', async () => {
    // P1: trivy-config CRITICAL alone, the need blocking on merge, a non-blocking push-layer copy listed first
    const pushNeed: Need = { id: 'iac', layer: 'push', category: 'iac', why: 't', blocking: false, floor: false };
    const mergeNeed: Need = { id: 'iac', layer: 'merge', category: 'iac', why: 't', blocking: true, floor: false };
    const spec = specFor(entry('trivy-config'), { needId: 'iac', choices: { severity: 'CRITICAL' } });
    const narrowSteps = renderStep(spec, entry('trivy-config'), p, { profile: imgProf, blocking: false }).steps;
    for (const needs of [[pushNeed, mergeNeed], [mergeNeed, pushNeed]]) {
      const d = draftOf({ profile: imgProf, needs, steps: [spec] });
      const r = await runWith([workflow({ iac: job([...renderJobPrelude({}, p).steps, ...narrowSteps]) })], d);
      expect(r.ok, `${needs[0]?.layer} first: ${show(r)}`).toBe(false);
      expect(r.notes.some((n) => /narrow a blocking check/.test(n)), `${needs[0]?.layer} first`).toBe(true);
    }
    // P7: build-push push true for a blocking merge need with a non-blocking push-layer copy first
    const pushBuild: Need = { id: 'image-build', layer: 'push', category: 'image-build', service: 'app', why: 't', blocking: false, floor: false };
    const r7 = await runWith([], draftOf({ profile: imgProf, needs: [pushBuild, needOf('image-build', 'app')], steps: [buildSpec('app', { push: 'true' })] }));
    expect(has(r7, 'unreviewed', /narrow/), show(r7)).toBe(true);
    // a spec with no need at all is refused (fail closed). GJ: it is now refused before it is rendered (a step without its need is no step of
    // pipegen's), so the narrowing note no longer appears; the outcome is the same refusal, stricter
    const orphan = await runWith([workflow({ iac: job([...renderJobPrelude({}, p).steps, ...narrowSteps]) })], draftOf({ profile: imgProf, needs: [], steps: [spec] }));
    expect(orphan.ok).toBe(false);
    expect(has(orphan, 'unreviewed', /The step for "iac" .*has no need of its own in the draft/), show(orphan)).toBe(true);
    // control: every copy non-blocking, the value may stand
    const r8 = await runWith([], draftOf({ profile: imgProf, needs: [pushBuild, needOf('image-build', 'app', false)], steps: [buildSpec('app', { push: 'true' })] }));
    expect(r8.issues.some((i) => /narrow/.test(i.message)), show(r8)).toBe(false);
  });

  it('referee: with the image build in the draft, only the archive form scans that service\'s image (G2-R1 I2)', async () => {
    // P5: the registry form of trivy-image, scanning some other image, next to the service's own image build
    const d = imageDraft();
    const other = `ghcr.io/library/clean@sha256:${'9'.repeat(64)}`;
    const reg = renderFindingsBlock(scanSpec(), TRIVY, p, { profile: imgProf, targets: { image: other } }, GATE);
    const r = await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': job(reg.steps, { outputs: jobOutputsFor(reg.steps) }) })], d);
    const notOurs = /not a step pipegen renders|differs from what pipegen renders/;
    expect(r.issues.some((i) => (i.check === 'unreviewed' || i.check === 'template') && notOurs.test(i.message) && /image-scan--app/.test(i.message)), show(r)).toBe(true);
    // and its base twin is no step of pipegen's either (B6: no base twin yet)
    const baseB = renderFindingsBlock(scanSpec(), TRIVY, p, { profile: imgProf, targets: { image: other }, base: true }, GATE);
    const baseSteps = [...renderJobPrelude({ baseRef: true }, p).steps, ...baseB.steps];
    const r2 = await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d), 'base-scan': job(baseSteps, { outputs: jobOutputsFor(baseSteps), permissions: { contents: 'read', actions: 'read' } }) })], d);
    expect(r2.issues.some((i) => /In the job "base-scan"/.test(i.message) && notOurs.test(i.message)), show(r2)).toBe(true);
    // the archive form still passes, and with no image build the registry form is as before
    expect(show(await runWith([imageFile({ 'image-build--app': buildJob(d), 'image-scan--app': scanJob(d) })], d))).toBe('');
    const noBuild = draftOf({ profile: imgProf, needs: [needOf('image-scan', 'app')], steps: [scanSpec()] });
    expect(show(await runWith([imageFile({ 'image-scan--app': job(reg.steps, { outputs: jobOutputsFor(reg.steps) }) })], noBuild))).toBe('');
  });

  it('referee: an image push runs only in a deploy job of pipegen.yml on a default-branch push (G2-R1 I3)', async () => {
    // (G15a-R10 r4-2, r4-3: the plan's tag, and the digest hand-off after the push)
    const bp = { id: BUILD_PUSH_STEP_ID, ...renderPlatformStep('build-push', p, { file: 'Dockerfile', tags: PUB_TAG }, { push: 'true' }) };
    const pub = (over: Job = {}): Job => job([...renderJobPrelude({}, p).steps, bp, ...publishTail()], { permissions: { contents: 'read', packages: 'write' }, ...over });
    const deploy = (over: Job = {}): Job => pub({ if: DEPLOY_PUSH_IF, needs: ['gate'], ...over });
    expect(show(await runWith([deployFile({ 'image-publish': deploy(), sign: keylessSign() })], signedDraft))).toBe('');
    const refused = (r: { issues: { check: string; message: string }[] }): boolean => has(r, 'permissions', /writes to the image registry/);
    // P6: a pull_request-only pipegen.yml, the push file, a default-push pipegen.yml job without the deploy condition, another file
    const cases: [string, CreatedFile][] = [
      ['pull_request only', deployFile({ 'image-publish': pub({ needs: ['gate'] }) }, { pull_request: null })],
      ['no deploy condition', deployFile({ 'image-publish': pub({ needs: ['gate'] }) })],
      ['the push file', { ...workflow({ 'image-publish': pub() }, { on: { push: featurePushTrigger('main') } }), path: PUSH_WORKFLOW }],
      ['another file', deployFile({ 'image-publish': deploy() }, DEPLOY_ON, '.github/workflows/release.yml')],
    ];
    for (const [name, f] of cases) {
      const r = await runWith([f], pubDraft);
      expect(refused(r), `${name}: ${show(r)}`).toBe(true);
    }
    // a pushing build with no packages permission is still a registry write attempt
    expect(refused(await runWith([imageFile({ release: job([...renderJobPrelude({}, p).steps, bp]) })], pubDraft))).toBe(true);
    // packages: write alone (a login with no push) is a registry write too; a no-push build without it is not
    const login = renderPlatformStep('docker-login', p, { username: '${{ github.actor }}', [['pass', 'word'].join('')]: `${'$'}{{ secrets.${['GITHUB', 'TOK' + 'EN'].join('_')} }}` }, { registry: 'ghcr.io' });
    expect(refused(await runWith([imageFile({ 'image-publish': job([login], { permissions: { contents: 'read', packages: 'write' } }) })], pubDraft))).toBe(true);
    const nopush = renderPlatformStep('build-push', p, { file: 'Dockerfile', tags: 'ghcr.io/o/r-app:x' }, { push: 'false' });
    expect(refused(await runWith([imageFile({ 'image-publish': job([...renderJobPrelude({}, p).steps, nopush]) })], pubDraft))).toBe(false);
  });

  it('referee: sign, verify and image hand-off steps in a composite action are refused (G2-R1 m1)', async () => {
    const klDraft = signingDraft(KEYLESS);
    const action = (steps: RenderedStep[]): CreatedFile => {
      const doc = new Document();
      doc.contents = doc.createNode({ name: 'x', description: 'x', runs: { using: 'composite' } });
      doc.setIn(['runs', 'steps'], doc.createNode(steps.map(({ usesComment: _c, ...rest }) => ({ ...rest, shell: rest.shell ?? undefined }))));
      return { path: '.github/actions/x/action.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'central' };
    };
    for (const [name, steps, d] of [
      ['verify', renderVerifySteps(COSIGN, klDraft, IMG), klDraft],
      ['sign', renderSignSteps(COSIGN, 'keyless', IMG), klDraft],
      ['image archive', renderImageBuild(buildSpec(), BUILD_PUSH, p, ictx()).steps.filter((x) => x.id === IMAGE_ARCHIVE_STEP_ID), imageDraft()],
    ] as const) {
      const r = await runWith([action([...steps])], d);
      expect(has(r, 'permissions', /composite action/), `${name}: ${show(r)}`).toBe(true);
    }
  });
});

describe('G2-R-sec2 (controller ruling): the sign job is held to the default-push rule', () => {
  it('referee: a sign job with packages write outside a default-push context → refused', async () => {
    const d = withPipeline(signingDraft(KEY_ENV));
    const keyEnv = renderSignSteps(COSIGN, 'key-env', IMG);
    const signJob = (over: Job = {}): Job => job([digestDownload(), ...keyEnv], { permissions: SIGN_PERMS, environment: 'pipegen-signing', ...over });
    const refused = (r: { issues: { check: string; message: string }[] }): boolean => has(r, 'permissions', /writes to the image registry/);
    const SIGN = './.github/workflows/sign.yml';
    // allowed: reached only from a deploy caller of pipegen.yml; or the sign job itself a deploy job of pipegen.yml
    expect(show(await runWith([signFile({ sign: signJob() }), deployCaller(d, SIGN)], d))).toBe('');
    const inline = workflow({ ...jobsOf(d), sign: signJob({ if: DEPLOY_PUSH_IF, needs: ['gate', 'image-publish'] }) }, { on: DEPLOY_ON_SIGN });
    expect(show(await runWith([inline], d))).toBe('');
    const cases: [string, CreatedFile[]][] = [
      ['a called file nobody judged calls', [signFile({ sign: signJob() })]],
      ['a caller without the deploy condition', [signFile({ sign: signJob() }), deployCaller(d, SIGN, { if: undefined })]],
      ['a caller in a pull_request-only pipegen.yml', [signFile({ sign: signJob() }), deployCaller(d, SIGN, {}, { pull_request: null })]],
      ['a second caller in another file', [signFile({ sign: signJob() }), deployCaller(d, SIGN), deployCaller(d, SIGN, { if: undefined, needs: [] }, { pull_request: null }, '.github/workflows/ci.yml')]],
      ['the only caller in another file, with the deploy condition', [signFile({ sign: signJob() }), deployCaller(d, SIGN, {}, DEPLOY_ON_SIGN, '.github/workflows/ci.yml')]],
      ['the called file runs on its own trigger too', [{ ...workflow({ sign: signJob() }, { on: { workflow_call: null, push: { branches: ['main'] } } }), path: '.github/workflows/sign.yml' }, deployCaller(d, SIGN)]],
      ['in pipegen.yml without the deploy condition', [workflow({ ...jobsOf(d), sign: signJob({ needs: ['gate'] }) }, { on: DEPLOY_ON_SIGN })]],
      ['in a pull_request-only pipegen.yml', [workflow({ ...jobsOf(d), sign: signJob() })]],
    ];
    for (const [name, files] of cases) {
      const r = await runWith(files, d);
      expect(r.issues.some((i) => i.check === 'permissions' && /writes to the image registry/.test(i.message) && /the job "sign"/.test(i.message)), `${name}: ${show(r)}`).toBe(true);
    }
    // a sign job with no registry write (keyless, id-token only) is not held to it
    const kl = withPipeline(signingDraft(KEYLESS));
    const klJob = job([digestDownload(), ...renderSignSteps(COSIGN, 'keyless', IMG)], { permissions: { contents: 'read', [OIDC]: 'write' } });
    expect(refused(await runWith([signFile({ sign: klJob })], kl))).toBe(false);
  });
});
