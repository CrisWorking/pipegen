// v0.2 Plan G Task 1, sub-task G3 (rulings S21, B3; carries from G2): the central files a private app repo calls from the owner's private
// `pipelines` repo. The one central file built here is the project's sign workflow; the per-layer files (merge, push, nightly) are G5's.
// - The signing mode is code-chosen and written as a literal of the file (S21): `signingMode(profile, caps)` for delivery, PROOF_SIGNING_MODE
//   (none) for the proof. A caller can only lower it to none, never pick another one; the file declares no workflow_call input, secret or
//   output, so no caller can pass a mode, an image or a key (the referee holds a workflow with a sign job to that, and recognises the sign
//   steps only as the draft's own render, signing.ts).
// - The file is the project's own (`<project>--sign.yml`, central-path.ts), not one file shared by every project of the owner: its content
//   is this draft's plan (image names and mode), so a shared file would be rewritten by each project's install. No `enrolled-repos.yml`
//   is written: the install records list the projects (S21).
// - Records-only `pipelines` (a public app: keyless signing in the app's own pipegen.yml, ruling B2) gets no central workflow.
// - The sign job (G2's one renderer, job `sign` only): the digest hand-off of each image (image-publish's artifact in the same run), the
//   reviewed ghcr login (cosign stores the signature next to the image), then cosign. key-env runs in environment pipegen-signing, whose
//   secrets hold the key (default-branch deploys only), with --tlog-upload=false (no public log for a private repo); keyless asks for the
//   OIDC token and the registry write that stores the signature (no environment, no key, no attestations). cache-mode: none. Attest mode
//   (actions/attest v4) can not be written yet: its subject-digest is a run-time value, and the reviewed input table (tool-flags.ts, inside
//   the gate bundle) takes only a literal digest (carry to G15, which also binds that digest to the image hand-off).
// - The caller job (G2-R-sec2): a deploy job of the app's pipegen.yml, `if: DEPLOY_PUSH_IF` (a push to the default branch), needing the
//   job that holds the gate, pinned to the recorded central commit, granted exactly the sign job's permissions, passing no secret (the
//   environment's secrets reach the called job through its own `environment:`). A repository outside pipegen's judged files can still call
//   the file; it then signs with its own environment and token, so pipegen can only judge the callers it writes.
import { Document } from 'yaml';
import { slug } from '../engine/artifact-names.js';
import { centralWorkflowFile } from '../engine/central-path.js';
import { DEPLOY_PUSH_IF, type RenderedStep } from '../engine/job-rules.js';
import { COMMIT_SHA_RE, isGitHubRepo } from '../engine/names.js';
import type { PlatformActions } from '../engine/pin.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { RenderError, show } from '../engine/render-error.js';
import { renderPlatformStep, stepsToYaml } from '../engine/render-step.js';
import { COSIGN_ID, imageDigestArtifact, renderSignSteps, type SignedImage } from '../engine/signing.js';
import { signingMode, type SigningMode } from '../github/signing-mode.js';
import type { Capabilities, CreatedFile, PipelineDraft, RepoProfile, ReviewedTool, SigningPlan } from '../types.js';

/** The sign job's id (the referee's permission and step tables are keyed by it). */
export const SIGN_JOB_ID = 'sign';
/** The job that pushes the image and uploads its digest hand-off (G7): the sign caller needs it. */
export const IMAGE_PUBLISH_JOB = 'image-publish';
/** The runner of the sign job: a pinned GitHub-hosted image. */
export const SIGN_RUNNER = 'ubuntu-24.04';
/** The sign job's own limit (a download, a login and one cosign call per image). */
export const SIGN_JOB_MINUTES = 15;
/** The one registry the sign job logs in to: the reviewed login sends the workflow token, which never goes to another registry. */
const SIGN_REGISTRY = 'ghcr.io';
/** The reviewed actions/attest major the attest mode is written for (plan Global Constraints). */
export const ATTEST_MAJOR = 'v4';

/** A mode that signs. */
export type SignMode = Exclude<SigningMode, 'none'>;

/**
 * The sign job's permissions per mode (the plan's "as the mode needs", inside the referee's sign row): `contents: read`, and the registry
 * write that stores the signature next to the image (both cosign modes, and attest's push-to-registry). The OIDC token only where the
 * signature comes from the job's identity (keyless; attest, whose actions/attest needs it for GitHub's signing); never in key-env, which
 * signs with the environment's key. `attestations: write` only in attest.
 */
const SIGN_PERMISSIONS: Readonly<Record<SignMode, Readonly<Record<string, 'read' | 'write'>>>> = Object.freeze({
  'key-env': Object.freeze({ contents: 'read', packages: 'write' }),
  keyless: Object.freeze({ contents: 'read', 'id-token': 'write', packages: 'write' }),
  attest: Object.freeze({ contents: 'read', 'id-token': 'write', packages: 'write', attestations: 'write' }),
});
export function signPermissions(mode: SignMode): Record<string, 'read' | 'write'> {
  const p = Object.hasOwn(SIGN_PERMISSIONS, mode) ? SIGN_PERMISSIONS[mode] : undefined;
  if (p === undefined) throw new RenderError(`${show(String(mode))} is not a signing mode that signs.`);
  return { ...p };
}

/** The job as the YAML holds it (steps rendered by stepsToYaml). */
export interface SignJob {
  name: string; 'runs-on': string; 'timeout-minutes': number; permissions: Record<string, 'read' | 'write'>;
  environment?: typeof SIGNING_ENVIRONMENT; 'cache-mode': 'none'; steps: RenderedStep[];
}

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
/** A job id as pipegen writes one (the referee's rule). */
const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;

/**
 * The mode a delivery may sign with: the code-chosen `signingMode(profile, caps)`, or none (the proof's PROOF_SIGNING_MODE, or a caller that
 * signs nothing). Anything else is refused: no caller picks a mode (keyless for a private repository would put its names in a public log).
 */
function checkedMode(p: RepoProfile, caps: Capabilities, mode: SigningMode): SigningMode {
  if (mode === 'none') return 'none';
  const chosen = signingMode(p, caps);
  if (mode !== chosen) throw new RenderError(`The signing mode is chosen from the repository and its probed capabilities (${show(chosen)} here), never passed in: ${show(String(mode))} is refused.`);
  return mode;
}

/**
 * The draft's signing plan (PipelineDraft.signing), filled by code (G2 carry): undefined for none. `images` are the images image-publish
 * pushes; key-env needs the sha256 of the public key pipegen generated before the setup PR (B3 c, made with signing.ts pubKeySha256), which the
 * verify step checks; the other modes carry none.
 */
export function signingPlan(p: RepoProfile, caps: Capabilities, mode: SigningMode, images: readonly SignedImage[], cosignPubSha256?: string): SigningPlan | undefined {
  const m = checkedMode(p, caps, mode);
  if (m === 'none') return undefined;
  const list = checkedImages(images);
  if (m === 'key-env') {
    if (typeof cosignPubSha256 !== 'string' || !SHA256_HEX_RE.test(cosignPubSha256)) throw new RenderError('Key-env signing needs the sha256 of the public key pipegen generated (64 lower-case hex), or no deploy could be verified.');
    return { mode: m, images: list, cosignPubSha256 };
  }
  if (cosignPubSha256 !== undefined) throw new RenderError(`A ${m} signature is not checked with a public key, so the plan carries none.`);
  return { mode: m, images: list };
}

/** The images, each a plain object of its service and repository, every service and repository once, at least one. */
function checkedImages(images: readonly SignedImage[]): SignedImage[] {
  if (!Array.isArray(images) || images.length === 0) throw new RenderError('There is no image to sign.');
  const services = new Set<string>();
  const repos = new Set<string>();
  return images.map((i) => {
    if (i === null || typeof i !== 'object' || typeof i.service !== 'string' || typeof i.repo !== 'string') throw new RenderError('A signed image is its service and its repository, both text.');
    let s: string;
    try { s = slug(i.service); } catch { throw new RenderError('A signed image belongs to a service with no letters or digits in its name.'); }
    if (services.has(s) || repos.has(i.repo)) throw new RenderError(`The image ${show(i.repo)} of ${show(i.service)} is listed twice.`);
    services.add(s);
    repos.add(i.repo);
    return { service: i.service, repo: i.repo };
  });
}

/**
 * The draft's plan for this mode, checked: the mode is the code-chosen one, and the draft's plan says the same mode. Null for none (nothing
 * signs). A plan for another mode, or none at all while the mode signs, is refused (fail closed: never a sign file the draft does not hold).
 */
function planFor(draft: PipelineDraft, mode: SigningMode): (SigningPlan & { mode: SignMode }) | null {
  const m = checkedMode(draft.profile, draft.capabilities, mode);
  if (m === 'none') return null;
  const plan = draft.signing;
  if (plan === undefined || plan === null || typeof plan !== 'object') throw new RenderError(`The signing mode is ${m}, but the draft records no signing plan, so there is nothing to sign.`);
  if (plan.mode !== m) throw new RenderError(`The draft's signing plan is ${show(String(plan.mode))}, but the signing mode is ${m}.`);
  checkedImages(plan.images);
  return { ...plan, mode: m };
}

/** The reviewed actions/attest entry of the platform actions, at the major the attest mode is written for. */
function attestAction(platform: PlatformActions): ReviewedTool {
  const t = platform?.attest;
  const c = t?.candidate;
  if (c?.repo !== 'actions/attest' || c.source !== 'reviewed' || c.reviewed !== true || t.step.action === undefined) throw new RenderError('Attest mode signs only with the reviewed actions/attest entry.');
  if (typeof c.version !== 'string' || !(c.version === ATTEST_MAJOR || c.version.startsWith(`${ATTEST_MAJOR}.`))) throw new RenderError(`Attest mode is written for actions/attest ${ATTEST_MAJOR}, not ${show(String(c.version))}.`);
  return t;
}

/**
 * The sign job for the draft in this mode (job `sign`): G2's renderer only. For a private repository it sits in the project's central sign
 * workflow (sharedWorkflows); for a public one (keyless) G5 places it in the app's pipegen.yml as a deploy job (`if: DEPLOY_PUSH_IF`, needs
 * the gate), the file keylessIdentity names. Throws a RenderError for none, a mode that is not the code-chosen one, a draft without the
 * matching plan, an image off ghcr.io, a missing reviewed entry, and attest mode (not writable yet, see the header).
 */
export function signJob(draft: PipelineDraft, mode: SigningMode, deps: { reviewed: readonly ReviewedTool[]; platform: PlatformActions }): SignJob {
  const plan = planFor(draft, mode);
  if (plan === null) throw new RenderError('The signing mode is none, so there is no sign job.');
  if (plan.mode === 'attest') {
    attestAction(deps.platform);
    throw new RenderError('Attest signing can not be written yet: actions/attest takes the image digest as a literal input only (the reviewed input table lives in the gate bundle), and the digest is known only when the deploy runs. It lands with the gate re-pin batch (G15); until then this repository is not signed.');
  }
  const cosign = deps.reviewed.find((t) => t.id === COSIGN_ID);
  if (cosign === undefined) throw new RenderError('The reviewed list has no cosign entry, so nothing can sign.');
  for (const i of plan.images) {
    if (!i.repo.startsWith(`${SIGN_REGISTRY}/`)) throw new RenderError(`The image ${show(i.repo)} is not on ${SIGN_REGISTRY}: the sign job stores the signature with the workflow token, which logs in to ${SIGN_REGISTRY} only.`);
  }
  const downloads = plan.images.map((i) => {
    const name = imageDigestArtifact(i.service);
    return renderPlatformStep('download-artifact', deps.platform, { name, path: `\${{ runner.temp }}/pipegen-out/${name}` });
  });
  const login = renderPlatformStep('docker-login', deps.platform, { username: '${{ github.actor }}', password: '${{ secrets.GITHUB_TOKEN }}' }, { registry: SIGN_REGISTRY });
  // one cosign install (the same reviewed release for every image), before the login (the order rule: nothing installs after a step it can
  // not see into), then each image's sign step
  const rendered = plan.images.map((i) => renderSignSteps(cosign, plan.mode as 'key-env' | 'keyless', i));
  const install = rendered[0]?.[0] as RenderedStep;
  for (const r of rendered) if (r.length !== 2 || JSON.stringify(r[0]) !== JSON.stringify(install)) throw new RenderError('The cosign install differs between images, so the sign job can not be written.');
  const job: SignJob = {
    name: 'pipegen sign', 'runs-on': SIGN_RUNNER, 'timeout-minutes': SIGN_JOB_MINUTES, permissions: signPermissions(plan.mode),
    'cache-mode': 'none', steps: [...downloads, install, login, ...rendered.map((r) => r[1] as RenderedStep)],
  };
  if (plan.mode === 'key-env') job.environment = SIGNING_ENVIRONMENT;
  return job;
}

/** The project's central sign workflow path (central-path.ts), from the draft's repository name. */
function signFilePath(draft: PipelineDraft): string {
  const project = draft.profile.repo;
  if (!isGitHubRepo(`${String(draft.profile.owner)}/${String(project)}`)) throw new RenderError(`The repository ${show(String(project))} is not a plain GitHub repository name.`);
  return centralWorkflowFile(project, 'sign');
}

/** Whether the central repo is records-only (a public app: its workflows are its own, ruling B2): no central workflow there. */
const recordsOnly = (draft: PipelineDraft): boolean => draft.profile.private !== true;

/**
 * The central files of the project that are not per layer: its sign workflow, `.github/workflows/<project>--sign.yml` (workflow_call only,
 * no input, the one job `sign`), or nothing for mode none, the proof, and a records-only `pipelines`. Throws as signJob does.
 */
export function sharedWorkflows(draft: PipelineDraft, mode: SigningMode, deps: { reviewed: readonly ReviewedTool[]; platform: PlatformActions }): CreatedFile[] {
  if (recordsOnly(draft)) return [];
  if (planFor(draft, mode) === null) return [];
  const job = signJob(draft, mode, deps);
  const path = signFilePath(draft);
  const doc = new Document();
  const { steps, ...rest } = job;
  doc.contents = doc.createNode({ name: 'pipegen sign', on: { workflow_call: {} }, permissions: {}, jobs: { [SIGN_JOB_ID]: rest } });
  doc.setIn(['jobs', SIGN_JOB_ID, 'steps'], stepsToYaml(steps));
  doc.commentBefore = ` pipegen: signs ${draft.profile.repo}'s images (${job.environment === undefined ? '' : `environment ${SIGNING_ENVIRONMENT}, `}${mode}); called only by its deploy job, written by pipegen.`;
  return [{ path, content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: `Signs the images of ${draft.profile.repo} after a push to its default branch (${mode}).`, repo: 'central' }];
}

/**
 * The app's caller job of the central sign workflow (for pipegen.yml, G5): a deploy job on a push to the default branch, needing the job
 * that holds the gate (and image-publish, whose digest it signs), pinned to the recorded central commit, granted exactly the sign job's
 * permissions, no input and no secret. Null when there is no central sign workflow (mode none, the proof, a records-only repo).
 */
export function signCallerJob(draft: PipelineDraft, mode: SigningMode, needs: readonly string[]): Record<string, unknown> | null {
  if (recordsOnly(draft)) return null;
  const plan = planFor(draft, mode);
  if (plan === null) return null;
  if (plan.mode === 'attest') throw new RenderError('Attest signing can not be written yet (see signJob), so there is no sign workflow to call.');
  if (!Array.isArray(needs) || needs.length === 0 || needs.some((n) => typeof n !== 'string' || !JOB_ID_RE.test(n)) || new Set(needs).size !== needs.length) {
    throw new RenderError('The sign caller needs the job holding the gate (and image-publish), each a plain job id, once.');
  }
  // G3-R2 M4: the digest it signs is image-publish's, uploaded earlier in the same run; without the need both would run at once
  if (!needs.includes(IMAGE_PUBLISH_JOB)) throw new RenderError(`The sign caller needs ${IMAGE_PUBLISH_JOB}, whose digest it signs (without it both run at once and the digest is not there yet).`);
  const pin = draft.centralPin;
  const owner = draft.profile.owner;
  if (pin === undefined || typeof pin.repo !== 'string' || typeof pin.sha !== 'string' || typeof owner !== 'string' || pin.repo.toLowerCase() !== `${owner.toLowerCase()}/pipelines` || !isGitHubRepo(pin.repo) || !COMMIT_SHA_RE.test(pin.sha)) {
    throw new RenderError('The sign workflow is called from the central <owner>/pipelines repo at the commit pipegen recorded, and the draft has no such central pin.');
  }
  return { uses: `${pin.repo}/${signFilePath(draft)}@${pin.sha}`, if: DEPLOY_PUSH_IF, needs: [...needs], permissions: signPermissions(plan.mode) };
}
