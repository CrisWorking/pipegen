// v0.2 Plan G, sub-task G2 (rulings B3 b and d; carries S-3, BP-3, BP-6): the one renderer of the signing and verification steps, from the
// reviewed entries. renderStep still refuses cosign (the sign job owns its flags, Plan B carry B6); these steps are rendered here only, and
// the referee recognises them only as this render of the draft's signing plan (PipelineDraft.signing), each kind in its own job:
// - sign (job `sign` only): the reviewed cosign release (checked by its sha256), then `cosign sign` of `<image>@<digest>`, the digest read
//   from pipegen's hand-off file and checked as sha256:<64 hex> before anything signs it. Attest mode (G15a): pipegen's digest step (the same
//   hand-off and check, the registry login, the digest as its output), then the reviewed actions/attest with that output as its subject.
//   key-env: the key and its password from the signing environment's secrets, `--tlog-upload=false` (no public log for a private repo)
//   and `--use-signing-config=false` (cosign 3 needs it for a key without the log). keyless: the job's GitHub OIDC identity, logged publicly.
// - verify (job `pipegen-verify` only):
//   key-env: the variable PIPEGEN_COSIGN_PUB is written to a fresh file, its sha256 is compared with the literal pipegen recorded
//   (DECISIONS #76: a writer can change the variable) BEFORE cosign reads that same file; then `cosign verify --key` of the image.
//   keyless: `cosign verify` with the sign job's exact identity and GitHub's OIDC issuer.
//   attest: `gh attestation verify` from the reviewed pinned gh release entry (installed by its sha256, run by its absolute path, never the
//   runner's gh), with the app repository and the central sign workflow as the signer.
// Every value written into a script is checked first (the image repository, the hash, the repository names); each is single-quoted.
import { createHash } from 'node:crypto';
import { slug } from './artifact-names.js';
import { DIGEST_FILE, IMAGE_DIGEST_ID, imageDigestArtifact } from './deploy-steps.js';
import { centralWorkflowFile } from './central-path.js';
import { ATTEST_DIGEST_STEP_ENV, attestDigestStepId, SIGN_STEP_ENV, signStepId, VERIFY_STEP_ENV, verifyStepId, type RenderedStep } from './job-rules.js';
import { isGitHubRepo } from './names.js';
import { pipegenScriptStep } from './pipegen-script.js';
import { releaseInstallStep } from './render-cli.js';
import { RenderError, show } from './render-error.js';
import { noImageServices } from './needs.js';
import type { Capabilities, PipelineDraft, RepoProfile, ReviewedTool, Service, SigningPlan } from '../types.js';

/**
 * GJ-R1 (review sec M3): the profile service a signing-plan image belongs to, matched by slug (the identity checkedImages and the digest
 * artifacts use). `reportOnly` when that service builds no image (noImageServices: its signing is report-only, the image leaves the plan);
 * not `reportOnly` when no profile service has that slug, or the name has no letters or digits (refused: nothing would build that image).
 */
export function signedImageOwner(p: RepoProfile, caps: Capabilities, service: unknown): { ok: true; service: Service } | { ok: false; reportOnly: boolean; why: string } {
  let k: string;
  try { k = slug(String(service)); } catch { return { ok: false, reportOnly: false, why: `${show(String(service))}, which is no service of the repository` }; }
  const owners = p.services.filter((s) => { try { return slug(s.name) === k; } catch { return false; } });
  if (typeof service !== 'string' || owners.length === 0) return { ok: false, reportOnly: false, why: `${show(String(service))}, which is no service of the repository` };
  // (GJ-R2, review GJ-r1 N6) unreachable today (needRefs refuses two services with one slug first), refused if it ever is
  if (owners.length > 1) return { ok: false, reportOnly: false, why: `${show(service)}, whose name matches more than one service of the repository` };
  const svc = owners[0] as Service;
  const why = noImageServices(p, caps).get(svc.name);
  return why === undefined ? { ok: true, service: svc } : { ok: false, reportOnly: true, why };
}

/** The reviewed entries the steps come from. GH_ID is the reviewed pinned gh release entry (ruling B3 d). */
export const COSIGN_ID = 'cosign';
export const GH_ID = 'gh';
const COSIGN_REPO = 'sigstore/cosign';
const GH_REPO = 'cli/cli';
/** GitHub's OIDC issuer: the only issuer a keyless signature is accepted from. */
/** The one registry the sign step logs in to (G3-R3): the workflow token never goes to another registry. */
export const SIGN_REGISTRY = 'ghcr.io';
export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
/** The keyless sign job lives in the app's caller workflow (ruling B2: the deploy jobs of pipegen.yml), so its certificate names that file. */
export const KEYLESS_SIGN_WORKFLOW = '.github/workflows/pipegen.yml';
/**
 * The project's central sign workflow (Plan G Task 1, built by src/layers/central.ts; G3 ruling: one file per project, `<project>--sign.yml`,
 * because its content is the draft's own plan): the attest-mode signer.
 */
export const centralSignWorkflow = (project: string): string => centralWorkflowFile(project, 'sign');
/** The digest hand-off: image-publish writes `sha256:<64 hex>` to this file of the service's digest artifact (B3 a; G7 brings it to the verify job). One source: deploy-steps.ts. */
export { DIGEST_FILE, IMAGE_DIGEST_ID, imageDigestArtifact };

/** One image the plan signs. */
export type SignedImage = SigningPlan['images'][number];

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
/** The image repository as signed: ghcr.io or docker.io, lower-case path segments, no tag, no digest (the attest subject-name rule, tighter). */
const IMAGE_REPO_RE = /^(?:ghcr\.io|docker\.io)(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*){1,10}$/;
/** A branch name as it may appear inside a single-quoted identity: plain characters only. */
const BRANCH_RE = /^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,200}$/;

/** The sha256 (hex) of the public key's exact text, as the verify step computes it from PIPEGEN_COSIGN_PUB (`printf '%s'`: no newline added). */
export function pubKeySha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** The certificate identity of the keyless sign job: the app's caller workflow on the default branch. */
export function keylessIdentity(p: Pick<RepoProfile, 'owner' | 'repo' | 'defaultBranch'>): string {
  const repo = `${p.owner}/${p.repo}`;
  if (!isGitHubRepo(repo)) throw new RenderError(`The repository ${show(repo)} is not a plain GitHub owner/name, so no signer identity can be written.`);
  if (typeof p.defaultBranch !== 'string' || !BRANCH_RE.test(p.defaultBranch)) throw new RenderError(`The default branch ${show(String(p.defaultBranch))} is not a plain branch name, so no signer identity can be written.`);
  return `https://github.com/${repo}/${KEYLESS_SIGN_WORKFLOW}@refs/heads/${p.defaultBranch}`;
}

/** The attest-mode signer workflow: the project's sign workflow in the central repository. */
export function attestSignerWorkflow(centralRepo: string, project: string): string {
  if (!isGitHubRepo(centralRepo) || !centralRepo.endsWith('/pipelines')) throw new RenderError(`The central repository ${show(centralRepo)} is not <owner>/pipelines.`);
  if (!isGitHubRepo(`${centralRepo.split('/')[0]}/${project}`)) throw new RenderError(`The project ${show(String(project))} is not a plain GitHub repository name.`);
  return `${centralRepo}/${centralSignWorkflow(project)}`;
}

function imageRepo(image: SignedImage): { repo: string; artifact: string } {
  if (typeof image?.repo !== 'string' || !IMAGE_REPO_RE.test(image.repo) || image.repo.length > 255) {
    throw new RenderError(`The image ${show(String(image?.repo))} is not a plain image repository on ghcr.io or docker.io (lower case, no tag, no digest).`);
  }
  try {
    slug(image.service);
  } catch {
    throw new RenderError('The signed image belongs to a service with no letters or digits in its name.');
  }
  return { repo: image.repo, artifact: imageDigestArtifact(image.service) };
}

/** The reviewed release entry, by id and repository, checked the way releaseInstallStep checks it. */
function reviewedRelease(tool: ReviewedTool, id: string, repo: string, exe: string): void {
  const c = tool?.candidate;
  if (tool?.id !== id || c?.id !== id || c.repo !== repo || c.kind !== 'cli' || c.source !== 'reviewed' || c.reviewed !== true) {
    throw new RenderError(`The step is rendered only from the reviewed ${id} entry (${repo}), not from ${show(String(tool?.id))}.`);
  }
  if (tool.step.cli?.install.method !== 'github-release' || tool.step.cli.command[0] !== exe) throw new RenderError(`The reviewed ${id} entry is not the ${exe} release binary.`);
}

const q = (s: string): string => `'${s}'`;
/** The lines that read the digest from the hand-off file and build `ref`: checked as sha256:<64 hex> before anything uses it. */
function refLines(repo: string, artifact: string): string[] {
  return [
    `digest_file="$RUNNER_TEMP/pipegen-out/${artifact}/${DIGEST_FILE}"`,
    'if [ ! -f "$digest_file" ] || [ -L "$digest_file" ]; then pg_fail "there is no image digest to work on"; fi',
    'digest="$(head -c 100 -- "$digest_file")"',
    'if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image digest is not sha256:<64 hex>"; fi',
    `ref=${q(repo)}"@$digest"`,
  ];
}
const runStep = pipegenScriptStep;
/** G7-R1 sec M1: the commit a signature names (the run's GITHUB_SHA), checked before cosign reads it. */
const COMMIT_LINE = 'if ! [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then pg_fail "this run\'s commit is not a 40-character commit, so the signature can not name it"; fi';

/** The sign steps of one image (job `sign` only): the reviewed cosign, then the sign of `<repo>@<digest>`. */
export function renderSignSteps(cosign: ReviewedTool, mode: 'key-env' | 'keyless', image: SignedImage): RenderedStep[] {
  reviewedRelease(cosign, COSIGN_ID, COSIGN_REPO, 'cosign');
  if (mode !== 'key-env' && mode !== 'keyless') throw new RenderError(`cosign signs only in key-env or keyless mode (attest mode signs with actions/attest), not ${show(String(mode))}.`);
  const { repo, artifact } = imageRepo(image);
  // G3-R3: the step logs in with the job's token, which only ever goes to ghcr.io
  if (!repo.startsWith(`${SIGN_REGISTRY}/`)) throw new RenderError(`The image ${show(repo)} is not on ${SIGN_REGISTRY}: the sign step logs in with the workflow token, which goes to ${SIGN_REGISTRY} only.`);
  const install = releaseInstallStep(cosign, 'pipegen-cosign-sign');
  const bin = `"${install.bin}"`;
  const pinned = cosign.candidate.pin.checksum;
  if (typeof pinned !== 'string' || !SHA256_HEX_RE.test(pinned)) throw new RenderError('The reviewed cosign entry has no sha256 pin, so the binary can not be checked before it signs.');
  // G3-R2 M3 (carry B-T1c, in the workflow): the binary is a regular file at its pinned sha256 again right before the first cosign call of
  // this step (a tripwire: since G3-R3 no other step of the job runs anything that is not pipegen's, see the referee's sign-job allowlist)
  const recheck = [
    `if [ ! -f ${bin} ] || [ -L ${bin} ]; then pg_fail "the cosign binary is not the regular file pipegen installed"; fi`,
    `printf '%s  %s\\n' ${q(pinned)} ${bin} | sha256sum --check --strict --status - || pg_fail "the cosign binary changed after its install (its sha256 is not the pinned one), so nothing is signed"`,
  ];
  // G3-R3: the registry login is cosign's own, in this step (no third-party action runs in the job that holds the key or the OIDC token): a
  // fresh config folder under RUNNER_TEMP, the job's token on stdin only (never on a command line), unset once used; the folder is removed
  // when the step ends, whatever happens
  const login = [
    'DOCKER_CONFIG="$(mktemp -d "$RUNNER_TEMP/pipegen-docker.XXXXXX")"',
    'export DOCKER_CONFIG',
    'trap \'rm -rf -- "$DOCKER_CONFIG"\' EXIT',
    `printf '%s' "$PIPEGEN_REGISTRY_TOKEN" | ${bin} login ${SIGN_REGISTRY} -u "$GITHUB_ACTOR" --password-stdin > /dev/null`,
    'unset PIPEGEN_REGISTRY_TOKEN',
  ];
  const sign = mode === 'key-env'
    // G7-R1 sec M1: the signature carries the commit it was made for (the gated push run's GITHUB_SHA); the verify step requires the same
    ? [COMMIT_LINE, `COSIGN_PASSWORD="$PIPEGEN_COSIGN_PASSWORD" ${bin} sign --yes --key env://PIPEGEN_COSIGN_KEY --tlog-upload=false --use-signing-config=false -a pipegen.commit="$GITHUB_SHA" "$ref"`]
    : [`${bin} sign --yes --oidc-provider=github-actions "$ref"`];
  const env = mode === 'key-env' ? { ...SIGN_STEP_ENV } : { PIPEGEN_REGISTRY_TOKEN: SIGN_STEP_ENV.PIPEGEN_REGISTRY_TOKEN as string };
  return [install.step, runStep(signStepId(repo), `pipegen: sign ${repo} (${mode})`, [...refLines(repo, artifact), ...recheck, ...login, ...sign], env)];
}

/**
 * G15a (carry C10; G3-R2 carry: the attest digest bound to the hand-off): the attest sign job's digest step of one image (job `sign` only, attest
 * mode): the digest image-publish uploaded (its hand-off file, checked as sha256:<64 hex>), the registry login actions/attest's
 * push-to-registry reads (the job's token on stdin only, unset once used; ghcr.io only), and the digest as the step's output `digest`, the
 * one value the attest step's subject-digest may name (tool-flags.ts RENDERER_INPUTS). The login is the docker CLI's (pipegen's own step,
 * no login action in a job that holds the OIDC token, G3-R3); it is stored in the runner's docker config, which a hosted runner drops with
 * the job, and the token is the job's own, which actions/attest already holds.
 */
export function renderAttestDigestStep(image: SignedImage): RenderedStep {
  const { repo, artifact } = imageRepo(image);
  if (!repo.startsWith(`${SIGN_REGISTRY}/`)) throw new RenderError(`The image ${show(repo)} is not on ${SIGN_REGISTRY}: the attest job logs in with the workflow token, which goes to ${SIGN_REGISTRY} only.`);
  return runStep(attestDigestStepId(repo), `pipegen: the digest of ${repo} to attest`, [
    ...refLines(repo, artifact),
    `printf '%s' "$PIPEGEN_REGISTRY_TOKEN" | /usr/bin/docker login ${SIGN_REGISTRY} -u "$GITHUB_ACTOR" --password-stdin > /dev/null`,
    'unset PIPEGEN_REGISTRY_TOKEN',
    'echo "digest=$digest" >> "$GITHUB_OUTPUT"',
  ], { ...ATTEST_DIGEST_STEP_ENV });
}

/**
 * The verify steps of one image (job `pipegen-verify` only), in the draft's signing mode: `tool` is the reviewed cosign entry (key-env,
 * keyless) or the reviewed gh entry (attest). Throws a RenderError for anything that can not be verified as recorded (no plan, no hash
 * literal, no central pin for attest, another entry).
 */
export function renderVerifySteps(tool: ReviewedTool, draft: PipelineDraft, image: SignedImage): RenderedStep[] {
  const plan = draft.signing;
  if (plan === undefined) throw new RenderError('The draft records no signing, so there is nothing to verify.');
  const { repo, artifact } = imageRepo(image);
  const id = verifyStepId(repo);
  const name = `pipegen: verify ${repo} (${plan.mode})`;
  if (plan.mode === 'attest') {
    reviewedRelease(tool, GH_ID, GH_REPO, 'gh');
    // G15a-R0b: attest mode is only a private repository's (signingMode), whose attestations GitHub's own instance signs, so gh runs with
    // --no-public-good and never fetches the public-good TUF (gh v2.103.3 pkg/cmd/attestation/verification/sigstore.go:78-79)
    if (draft.profile.private !== true) throw new RenderError('Attest mode is for private repositories only; a public repository signs keyless.');
    const central = draft.centralPin?.repo;
    if (central === undefined) throw new RenderError('Attest mode verifies against the central sign workflow, and the draft has no central pin.');
    const signer = attestSignerWorkflow(central, draft.profile.repo);
    // controller ruling G2-R-sec 2: bound like keyless. The source is the app's default branch; the signer is the central sign workflow at
    // the commit pipegen pinned (a reusable workflow called at a commit signs with that commit, so --signer-digest binds its ref; gh's
    // --signer-workflow takes no ref, and is a prefix regex, safe only with --signer-digest); never a self-hosted runner. G15a: and the
    // deployed commit itself (--source-digest, the same commit source as key-env and keyless, G7-R1 sec M1: the verify job runs only for a
    // push deploy, so it is GITHUB_SHA, checked as 40 hex first). Flags: the pinned entry's version (reviewed-tools.yml gh comment).
    const centralSha = draft.centralPin?.sha;
    if (typeof centralSha !== 'string' || !COMMIT_RE.test(centralSha)) throw new RenderError('Attest mode binds the signer to the central commit pipegen pinned, and the draft has no 40-character central commit.');
    const branch = draft.profile.defaultBranch;
    if (typeof branch !== 'string' || !BRANCH_RE.test(branch)) throw new RenderError(`The default branch ${show(String(branch))} is not a plain branch name, so the attestation's source ref can not be bound.`);
    const app = `${draft.profile.owner}/${draft.profile.repo}`;
    if (!isGitHubRepo(app)) throw new RenderError(`The repository ${show(app)} is not a plain GitHub owner/name.`);
    const install = releaseInstallStep(tool, 'pipegen-gh-verify');
    return [install.step, runStep(id, name, [
      ...refLines(repo, artifact),
      // a fresh config folder: the runner's own gh login or config is never read
      'ghcfg="$(mktemp -d "$RUNNER_TEMP/pipegen-gh.XXXXXX")"',
      COMMIT_LINE,
      `GH_TOKEN="$PIPEGEN_GH_TOKEN" GH_CONFIG_DIR="$ghcfg" GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 "${install.bin}" attestation verify "oci://$ref" --repo ${q(app)} --source-ref ${q(`refs/heads/${branch}`)} --source-digest "$GITHUB_SHA" --signer-workflow ${q(signer)} --signer-digest ${q(centralSha)} --no-public-good --deny-self-hosted-runners`,
    ], { PIPEGEN_GH_TOKEN: VERIFY_STEP_ENV.PIPEGEN_GH_TOKEN as string })];
  }
  reviewedRelease(tool, COSIGN_ID, COSIGN_REPO, 'cosign');
  const install = releaseInstallStep(tool, 'pipegen-cosign-verify');
  const bin = `"${install.bin}"`;
  // G7: the signature is read from the registry, so cosign logs in first (a private package answers no one else), the same way the sign
  // step does (G3-R3): a fresh config folder, the job's own token (packages: read) on stdin only, unset once used, the folder removed at the end
  const login = [
    'DOCKER_CONFIG="$(mktemp -d "$RUNNER_TEMP/pipegen-docker.XXXXXX")"',
    'export DOCKER_CONFIG',
    'trap \'rm -rf -- "$DOCKER_CONFIG"\' EXIT',
    `printf '%s' "$PIPEGEN_REGISTRY_TOKEN" | ${bin} login ${SIGN_REGISTRY} -u "$GITHUB_ACTOR" --password-stdin > /dev/null`,
    'unset PIPEGEN_REGISTRY_TOKEN',
  ];
  const token = { PIPEGEN_REGISTRY_TOKEN: VERIFY_STEP_ENV.PIPEGEN_REGISTRY_TOKEN as string };
  if (!repo.startsWith(`${SIGN_REGISTRY}/`)) throw new RenderError(`The image ${show(repo)} is not on ${SIGN_REGISTRY}: the verify step logs in with the workflow token, which goes to ${SIGN_REGISTRY} only.`);
  if (plan.mode === 'keyless') {
    const app = `${draft.profile.owner}/${draft.profile.repo}`;
    if (!isGitHubRepo(app)) throw new RenderError(`The repository ${show(app)} is not a plain GitHub owner/name.`);
    return [install.step, runStep(id, name, [
      ...refLines(repo, artifact),
      ...login,
      COMMIT_LINE,
      // G7-R1 sec M1: the certificate's workflow run is a push of this repository for the deployed commit, so an older pipegen-signed image
      // put in the digest's place (another artifact, an older digest) does not pass
      `${bin} verify --certificate-identity ${q(keylessIdentity(draft.profile))} --certificate-oidc-issuer ${q(GITHUB_OIDC_ISSUER)} --certificate-github-workflow-sha "$GITHUB_SHA" --certificate-github-workflow-trigger push --certificate-github-workflow-repository ${q(app)} "$ref" > /dev/null`,
    ], token)];
  }
  if (plan.mode !== 'key-env') throw new RenderError(`The signing mode ${show(String(plan.mode))} is not one pipegen verifies.`);
  const want = plan.cosignPubSha256;
  if (typeof want !== 'string' || !SHA256_HEX_RE.test(want)) throw new RenderError('Key-env verification needs the sha256 of the public key pipegen recorded (64 lower-case hex): without it the variable can not be trusted.');
  return [install.step, runStep(id, name, [
    // DECISIONS #76 (G7: first, before any other check): the variable is writer-controlled; only the key pipegen recorded is trusted, and its
    // sha256 is checked before anything else runs, so cosign only ever reads that same file
    `want=${q(want)}`,
    'keydir="$(mktemp -d "$RUNNER_TEMP/pipegen-cosign-key.XXXXXX")"',
    'printf \'%s\' "$PIPEGEN_COSIGN_PUB" > "$keydir/cosign.pub"',
    'got="$(sha256sum -- "$keydir/cosign.pub" | cut -d \' \' -f 1)"',
    'if [ "$got" != "$want" ]; then pg_fail "PIPEGEN_COSIGN_PUB is not the public key pipegen recorded (its sha256 differs), so this deploy is not verified"; fi',
    ...refLines(repo, artifact),
    ...login,
    // G7-R1 sec M1: only a signature made for this commit (the sign step's annotation) passes
    COMMIT_LINE,
    `${bin} verify --key "$keydir/cosign.pub" --insecure-ignore-tlog=true -a pipegen.commit="$GITHUB_SHA" "$ref" > /dev/null`,
  ], { PIPEGEN_COSIGN_PUB: VERIFY_STEP_ENV.PIPEGEN_COSIGN_PUB as string, ...token })];
}

/** What the referee expects for a draft: the sign and verify steps per image, or why they can not be rendered (notes). */
export function expectedSigningSteps(draft: PipelineDraft, reviewed: readonly ReviewedTool[]): { sign: RenderedStep[][]; verify: RenderedStep[][]; notes: string[] } {
  const out = { sign: [] as RenderedStep[][], verify: [] as RenderedStep[][], notes: [] as string[] };
  const plan = draft.signing;
  if (plan === undefined) return out;
  const cosign = reviewed.find((t) => t.id === COSIGN_ID);
  const gh = reviewed.find((t) => t.id === GH_ID);
  for (const image of Array.isArray(plan.images) ? plan.images : []) {
    const attempt = (what: string, f: () => RenderedStep[]): RenderedStep[] | null => {
      try { return f(); } catch (e) {
        if (!(e instanceof RenderError)) throw e;
        out.notes.push(`The ${what} steps of ${show(String(image?.repo))} can not be rendered, so no step may claim to be them: ${e.message}`);
        return null;
      }
    };
    // G15a: attest mode's own sign-kind step is the digest step (the attest step itself is the reviewed actions/attest, judged as an action)
    const s = plan.mode === 'attest' ? attempt('sign', () => [renderAttestDigestStep(image)])
      : attempt('sign', () => { if (cosign === undefined) throw new RenderError('the reviewed list has no cosign entry'); return renderSignSteps(cosign, plan.mode as 'key-env' | 'keyless', image); });
    if (s !== null) out.sign.push(s);
    const tool = plan.mode === 'attest' ? gh : cosign;
    const v = attempt('verify', () => { if (tool === undefined) throw new RenderError(`the reviewed list has no ${plan.mode === 'attest' ? 'gh (the pinned gh release)' : 'cosign'} entry`); return renderVerifySteps(tool, draft, image); });
    if (v !== null) out.verify.push(v);
  }
  return out;
}
