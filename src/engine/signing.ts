// v0.2 Plan G, sub-task G2 (rulings B3 b and d; carries S-3, BP-3, BP-6): the one renderer of the signing and verification steps, from the
// reviewed entries. renderStep still refuses cosign (the sign job owns its flags, Plan B carry B6); these steps are rendered here only, and
// the referee recognises them only as this render of the draft's signing plan (PipelineDraft.signing), each kind in its own job:
// - sign (job `sign` only): the reviewed cosign release (checked by its sha256), then `cosign sign` of `<image>@<digest>`, the digest read
//   from pipegen's hand-off file and checked as sha256:<64 hex> before anything signs it.
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
import { resultArtifactName, slug } from './artifact-names.js';
import { centralWorkflowFile } from './central-path.js';
import { SIGN_STEP_ENV, signStepId, VERIFY_STEP_ENV, verifyStepId, type RenderedStep } from './job-rules.js';
import { isGitHubRepo } from './names.js';
import { pipegenScriptStep } from './pipegen-script.js';
import { releaseInstallStep } from './render-cli.js';
import { RenderError, show } from './render-error.js';
import type { PipelineDraft, RepoProfile, ReviewedTool, SigningPlan } from '../types.js';

/** The reviewed entries the steps come from. GH_ID is the reviewed pinned gh release entry (it lands in G15's re-pin batch, ruling B3 d). */
export const COSIGN_ID = 'cosign';
export const GH_ID = 'gh';
const COSIGN_REPO = 'sigstore/cosign';
const GH_REPO = 'cli/cli';
/** GitHub's OIDC issuer: the only issuer a keyless signature is accepted from. */
export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
/** The keyless sign job lives in the app's caller workflow (ruling B2: the deploy jobs of pipegen.yml), so its certificate names that file. */
export const KEYLESS_SIGN_WORKFLOW = '.github/workflows/pipegen.yml';
/**
 * The project's central sign workflow (Plan G Task 1, built by src/layers/central.ts; G3 ruling: one file per project, `<project>--sign.yml`,
 * because its content is the draft's own plan): the attest-mode signer.
 */
export const centralSignWorkflow = (project: string): string => centralWorkflowFile(project, 'sign');
/** The digest hand-off: image-publish writes `sha256:<64 hex>` to this file of the service's digest artifact (B3 a; G7 brings it to the verify job). */
export const IMAGE_DIGEST_ID = 'image-digest';
export const DIGEST_FILE = 'digest';
export const imageDigestArtifact = (service: string): string => resultArtifactName(IMAGE_DIGEST_ID, service);

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

/** The sign steps of one image (job `sign` only): the reviewed cosign, then the sign of `<repo>@<digest>`. */
export function renderSignSteps(cosign: ReviewedTool, mode: 'key-env' | 'keyless', image: SignedImage): RenderedStep[] {
  reviewedRelease(cosign, COSIGN_ID, COSIGN_REPO, 'cosign');
  if (mode !== 'key-env' && mode !== 'keyless') throw new RenderError(`cosign signs only in key-env or keyless mode (attest mode signs with actions/attest), not ${show(String(mode))}.`);
  const { repo, artifact } = imageRepo(image);
  const install = releaseInstallStep(cosign, 'pipegen-cosign-sign');
  const bin = `"${install.bin}"`;
  const pinned = cosign.candidate.pin.checksum;
  if (typeof pinned !== 'string' || !SHA256_HEX_RE.test(pinned)) throw new RenderError('The reviewed cosign entry has no sha256 pin, so the binary can not be checked before it signs.');
  // G3-R2 M3 (carry B-T1c, in the workflow): other steps (the registry login) run between the install and this step, so the binary is a regular
  // file at its pinned sha256 again right before the one cosign call that sees the key
  const recheck = [
    `if [ ! -f ${bin} ] || [ -L ${bin} ]; then pg_fail "the cosign binary is not the regular file pipegen installed"; fi`,
    `printf '%s  %s\\n' ${q(pinned)} ${bin} | sha256sum --check --strict --status - || pg_fail "the cosign binary changed after its install (its sha256 is not the pinned one), so nothing is signed"`,
  ];
  const sign = mode === 'key-env'
    ? [`COSIGN_PASSWORD="$PIPEGEN_COSIGN_PASSWORD" ${bin} sign --yes --key env://PIPEGEN_COSIGN_KEY --tlog-upload=false --use-signing-config=false "$ref"`]
    : [`${bin} sign --yes --oidc-provider=github-actions "$ref"`];
  return [install.step, runStep(signStepId(repo), `pipegen: sign ${repo} (${mode})`, [...refLines(repo, artifact), ...recheck, ...sign], mode === 'key-env' ? { ...SIGN_STEP_ENV } : {})];
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
    const central = draft.centralPin?.repo;
    if (central === undefined) throw new RenderError('Attest mode verifies against the central sign workflow, and the draft has no central pin.');
    const signer = attestSignerWorkflow(central, draft.profile.repo);
    // controller ruling G2-R-sec 2: bound like keyless. The source is the app's default branch; the signer is the central sign workflow at
    // the commit pipegen pinned (a reusable workflow called at a commit signs with that commit, so --signer-digest binds its ref; gh's
    // --signer-workflow takes no ref); never a self-hosted runner. Flags checked against gh 2.87.3's help; the pinned entry's version: live checklist.
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
      `GH_TOKEN="$PIPEGEN_GH_TOKEN" GH_CONFIG_DIR="$ghcfg" GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 "${install.bin}" attestation verify "oci://$ref" --repo ${q(app)} --source-ref ${q(`refs/heads/${branch}`)} --signer-workflow ${q(signer)} --signer-digest ${q(centralSha)} --deny-self-hosted-runners`,
    ], { PIPEGEN_GH_TOKEN: VERIFY_STEP_ENV.PIPEGEN_GH_TOKEN as string })];
  }
  reviewedRelease(tool, COSIGN_ID, COSIGN_REPO, 'cosign');
  const install = releaseInstallStep(tool, 'pipegen-cosign-verify');
  const bin = `"${install.bin}"`;
  if (plan.mode === 'keyless') {
    return [install.step, runStep(id, name, [
      ...refLines(repo, artifact),
      `${bin} verify --certificate-identity ${q(keylessIdentity(draft.profile))} --certificate-oidc-issuer ${q(GITHUB_OIDC_ISSUER)} "$ref" > /dev/null`,
    ])];
  }
  if (plan.mode !== 'key-env') throw new RenderError(`The signing mode ${show(String(plan.mode))} is not one pipegen verifies.`);
  const want = plan.cosignPubSha256;
  if (typeof want !== 'string' || !SHA256_HEX_RE.test(want)) throw new RenderError('Key-env verification needs the sha256 of the public key pipegen recorded (64 lower-case hex): without it the variable can not be trusted.');
  return [install.step, runStep(id, name, [
    ...refLines(repo, artifact),
    `want=${q(want)}`,
    'keydir="$(mktemp -d "$RUNNER_TEMP/pipegen-cosign-key.XXXXXX")"',
    'printf \'%s\' "$PIPEGEN_COSIGN_PUB" > "$keydir/cosign.pub"',
    'got="$(sha256sum -- "$keydir/cosign.pub" | cut -d \' \' -f 1)"',
    // DECISIONS #76: the variable is writer-controlled; only the key pipegen recorded is trusted, and it is checked before cosign reads it
    'if [ "$got" != "$want" ]; then pg_fail "PIPEGEN_COSIGN_PUB is not the public key pipegen recorded (its sha256 differs), so this deploy is not verified"; fi',
    `${bin} verify --key "$keydir/cosign.pub" --insecure-ignore-tlog=true "$ref" > /dev/null`,
  ], { PIPEGEN_COSIGN_PUB: VERIFY_STEP_ENV.PIPEGEN_COSIGN_PUB as string })];
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
    if (plan.mode !== 'attest') {
      const s = attempt('sign', () => { if (cosign === undefined) throw new RenderError('the reviewed list has no cosign entry'); return renderSignSteps(cosign, plan.mode as 'key-env' | 'keyless', image); });
      if (s !== null) out.sign.push(s);
    }
    const tool = plan.mode === 'attest' ? gh : cosign;
    const v = attempt('verify', () => { if (tool === undefined) throw new RenderError(`the reviewed list has no ${plan.mode === 'attest' ? 'gh (the pinned gh release lands in the re-pin batch, G15)' : 'cosign'} entry`); return renderVerifySteps(tool, draft, image); });
    if (v !== null) out.verify.push(v);
  }
  return out;
}
