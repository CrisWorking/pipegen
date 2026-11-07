// v0.2 Plan G G7 (rulings B3 a, c; carries G1→G7 deploy order, G2→G7 digest download by run id, G2 order exception for the digest
// upload): pipegen's own fixed steps of the deploy layer, each one renderer shared by the builders (src/layers) and the referee, which
// recognises them only by their exact content (like the pr-check lookup and the image hand-off).
// - image-publish (job `image-publish` only): after the reviewed build-push step (`id: pipegen-build-push`, push true), the publish digest
//   step writes the pushed image's digest, checked as sha256:<64 hex> and (G15a-R11 r5-1) proven by the daemon's RepoDigests of the image the
//   job built, to `$RUNNER_TEMP/pipegen-out/<digest artifact>/digest`; the folder is
//   then uploaded as the service's digest artifact (`pipegen-out-image-digest--<svc>`, G2's name: B3 a's `pipegen-image-digest` does not pass
//   the gate-bundled upload name checker). That tail is the order rule's exception for this job (job-rules.ts publishTailAt).
// - pipegen-verify (job `pipegen-verify` only), after the gate action's find-run step (`id: pipegen-find-run`):
//   - the head check: the deploy runs on the default branch, and the deployed commit is still that branch's head (a deploy of an older
//     commit after a newer one is refused; parallel default-branch runs each finish, G1-R1);
//   - the digest step: the digest artifact of exactly the run find-run proved (by its run id, through the API with the job's token: the
//     reviewed download-artifact form takes no run id, and its input table is in the gate bundle), the one entry `digest`, checked as
//     sha256:<64 hex> before anything reads it, written where the verify steps read it, and output as `digest` (the job output).
// Every literal written into a script is checked first (the default branch, the artifact name) and single-quoted.
import { resultArtifactName, slug } from './artifact-names.js';
import type { RenderedStep } from './job-rules.js';
import { pipegenScriptStep } from './pipegen-script.js';
import { RenderError, show } from './render-error.js';

/** The find-run step's id in the verify job (its run-id output feeds the digest step). */
export const FIND_RUN_STEP_ID = 'pipegen-find-run';
/** The id of the reviewed build-push step in image-publish (its digest output feeds the publish digest step). */
export const BUILD_PUSH_STEP_ID = 'pipegen-build-push';
/** The verify job's head check and digest step, and image-publish's digest step. */
export const HEAD_CHECK_STEP_ID = 'pipegen-head-check';
export const DIGEST_STEP_ID = 'pipegen-digest';
export const PUBLISH_DIGEST_STEP_ID = 'pipegen-publish-digest';
/** The digest hand-off (B3 a): the artifact of a service's pushed image digest and its one file (signing.ts reads the same). */
export const IMAGE_DIGEST_ID = 'image-digest';
export const DIGEST_FILE = 'digest';
export const imageDigestArtifact = (service: string): string => resultArtifactName(IMAGE_DIGEST_ID, service);
/** The tag image-publish pushes (the digest, never the tag, is what is signed, verified and handed to the deploy). */
export const PUBLISH_TAG = 'pipegen';

/** The image repository pipegen publishes a service's image to (no tag, no digest): `ghcr.io/<owner>/<repo>-<service slug>`, lower case. */
const IMAGE_REPO_RE = /^ghcr\.io(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*){2}$/;
export function publishedImageRepo(owner: string, repo: string, service: string): string {
  let s: string;
  try { s = slug(service); } catch { throw new RenderError('A published image belongs to a service with letters or digits in its name.'); }
  const r = `ghcr.io/${String(owner).toLowerCase()}/${String(repo).toLowerCase()}-${s}`;
  if (!IMAGE_REPO_RE.test(r) || r.length > 255) throw new RenderError(`The image repository ${show(r)} is not a plain ghcr.io repository (lower-case letters and digits, single . _ or - between them).`);
  return r;
}

/** The head check's working-directory (G7-R2 1a): the one expression checkExpressions accepts in that field, on that step only. */
export const HEAD_CHECK_DIR = '${{ runner.temp }}';
/** The one expression each step's env holds, exactly (job-rules.ts checkExpressions accepts these and nothing else for these ids). */
export const HEAD_CHECK_ENV: Readonly<Record<string, string>> = Object.freeze({ PIPEGEN_HEAD_TOKEN: '${{ github.token }}' });
export const DIGEST_STEP_ENV: Readonly<Record<string, string>> = Object.freeze({
  PIPEGEN_RUN_ID: `\${{ steps.${FIND_RUN_STEP_ID}.outputs.run-id }}`, PIPEGEN_DIGEST_TOKEN: '${{ github.token }}',
});
export const PUBLISH_DIGEST_ENV: Readonly<Record<string, string>> = Object.freeze({
  PIPEGEN_IMAGE_DIGEST: `\${{ steps.${BUILD_PUSH_STEP_ID}.outputs.digest }}`, PIPEGEN_IMAGE_ID: `\${{ steps.${BUILD_PUSH_STEP_ID}.outputs.imageid }}`,
});

/** A branch name as it may appear inside a single-quoted literal and an API path: plain characters only (signing.ts's rule). */
const BRANCH_RE = /^(?!-)(?!.*\.\.)(?!.*\/\/)(?!.*\/$)[A-Za-z0-9._/-]{1,200}$/;
/** An artifact name as it may appear inside a single-quoted literal and a query string. */
const ARTIFACT_RE = /^pipegen-out-[a-z0-9][a-z0-9-]{0,120}$/;
const q = (s: string): string => `'${s}'`;
const branchOf = (b: unknown): string => {
  if (typeof b !== 'string' || !BRANCH_RE.test(b)) throw new RenderError(`The default branch ${show(String(b))} is not a plain branch name, so the deploy can not be checked against it.`);
  return b;
};
const artifactOf = (service: string): string => {
  let a: string;
  try { slug(service); a = imageDigestArtifact(service); } catch { throw new RenderError('An image digest belongs to a service with letters or digits in its name.'); }
  if (!ARTIFACT_RE.test(a)) throw new RenderError(`The digest artifact name ${show(a)} is not one pipegen writes.`);
  return a;
};
/** The lines that fail unless `$1` (a variable name) holds a plain positive id (a run or an artifact). */
const idCheck = (v: string, what: string): string => `if ! [[ "$${v}" =~ ^[1-9][0-9]{0,19}$ ]]; then pg_fail "${what}"; fi`;
/**
 * A call with the job's token: the header goes to curl on stdin (`-H @-`), never on its command line, where any process of the runner could
 * read it (G3-R3 "token on stdin only"; G7-R1 sec M5).
 */
const CURL = "printf 'Authorization: Bearer %s\\n' \"$TOKEN\" | curl -fsS --proto '=https' --max-time 60 -H @- -H 'Accept: application/vnd.github+json'";

/**
 * The head check of the verify job (carry G1→G7): this run is a push to the default branch, and the deployed commit (GITHUB_SHA, the
 * commit find-run proved) is still the head of that branch when the check runs, after find-run's wait. Otherwise the deploy is refused: a
 * newer commit is on the branch, and its own run deploys it (an older commit never deploys after a newer one). The job's token reads the ref.
 */
export function renderHeadCheckStep(defaultBranch: string): RenderedStep {
  const branch = branchOf(defaultBranch);
  const step = pipegenScriptStep(HEAD_CHECK_STEP_ID, 'pipegen: the deployed commit is the head of the default branch', [
    // G7-R2 1b: the check runs on the user's own runner or container too (the first step of each gated deploy job), so it says plainly which
    // tool is missing rather than failing with "command not found"
    'for t in curl jq; do command -v "$t" > /dev/null || pg_fail "this job\'s runner or container has no $t, which pipegen\'s head check needs; install $t there, or run this deploy job on ubuntu-latest"; done',
    `want=${q(branch)}`,
    // G7-R1 sec M2: a push only. For workflow_run, issue_comment or pull_request_target GITHUB_REF is the default branch and GITHUB_SHA its
    // head, while the job may deploy another commit (the other run's, a pull request's)
    'if [ "$GITHUB_EVENT_NAME" != "push" ]; then pg_fail "this run is not a push (it is $GITHUB_EVENT_NAME), so pipegen does not let it deploy; deploy by pushing to the default branch"; fi',
    'if [ "$GITHUB_REF" != "refs/heads/$want" ]; then pg_fail "this push is not to the default branch, so pipegen does not let it deploy"; fi',
    'if ! [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]; then pg_fail "the deployed commit is not a 40-character commit"; fi',
    'TOKEN="$PIPEGEN_HEAD_TOKEN"',
    'unset PIPEGEN_HEAD_TOKEN',
    `head="$(${CURL} "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/git/ref/heads/$want" | jq -er 'if .object.type == "commit" and (.object.sha | type) == "string" then .object.sha else error("not a branch head") end')"`,
    'if [ "$head" != "$GITHUB_SHA" ]; then pg_fail "the default branch has moved on to a newer commit, so this older commit is not deployed (the newer commit\'s own run deploys it if that commit starts a deploy; otherwise push again or re-run all jobs on the newest commit)"; fi',
  ], { ...HEAD_CHECK_ENV });
  // G7-R2 1a: its own working folder, the runner's temp folder (it exists before any checkout, on every runner and in every container), so a
  // job's `defaults.run.working-directory` (often a folder the checkout makes) does not apply to it
  return { ...step, 'working-directory': HEAD_CHECK_DIR };
}

/**
 * The digest step of the verify job for the image of `service` (B3 a, carry G2→G7): the digest artifact of the run find-run proved, read
 * by that run's id (exactly one artifact of that name, of that run, not expired: a run past the artifact retention fails closed with that
 * reason), its one entry `digest` (at most 100 bytes), checked as sha256:<64 hex>, written to the file the verify steps read, then output.
 */
export function renderDigestStep(service: string): RenderedStep {
  const artifact = artifactOf(service);
  return pipegenScriptStep(DIGEST_STEP_ID, `pipegen: the image digest of ${slug(service)} from the gated run`, [
    'run_id="$PIPEGEN_RUN_ID"',
    idCheck('run_id', 'find-run gave no run id, so there is no gated run to read the digest from'),
    'TOKEN="$PIPEGEN_DIGEST_TOKEN"',
    'unset PIPEGEN_DIGEST_TOKEN',
    'api="$GITHUB_API_URL/repos/$GITHUB_REPOSITORY"',
    `list="$(${CURL} "$api/actions/runs/$run_id/artifacts?name=${artifact}&per_page=2")"`,
    `id="$(printf '%s' "$list" | jq -er --arg n ${q(artifact)} --arg run "$run_id" 'if (.artifacts | type) == "array" and (.artifacts | length) == 1 and .artifacts[0].name == $n and (.artifacts[0].workflow_run.id | tostring) == $run then .artifacts[0].id | tostring else error("not exactly one digest artifact of the gated run") end')"`,
    idCheck('id', 'the gated run has no digest artifact of this image'),
    `if ! printf '%s' "$list" | jq -e '.artifacts[0].expired == false' > /dev/null; then pg_fail "the gated run's image digest has expired (the run is past the artifact retention period); push to the default branch again to deploy"; fi`,
    `dir="$RUNNER_TEMP/pipegen-out/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-out"',
    'mkdir "$dir"',
    'zip="$(mktemp "$RUNNER_TEMP/pipegen-digest.XXXXXX")"',
    // one redirect only (GitHub sends the zip from its results storage; sec M6); curl drops the token on a redirect to another host
    `${CURL.replace("--proto '=https'", "--proto '=https' --proto-redir '=https' -L --max-redirs 1 --max-filesize 65536")} "$api/actions/artifacts/$id/zip" -o "$zip"`,
    'unset TOKEN',
    `unzip -p -- "$zip" ${q(DIGEST_FILE)} | head -c 100 > "$dir/${DIGEST_FILE}"`,
    'rm -f -- "$zip"',
    `digest="$(cat -- "$dir/${DIGEST_FILE}")"`,
    'if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image digest of the gated run is not sha256:<64 hex>"; fi',
    'echo "digest=$digest" >> "$GITHUB_OUTPUT"',
  ], { ...DIGEST_STEP_ENV });
}

/**
 * The publish digest step of image-publish for the image of `service`, published to `imageRepo` (publishedImageRepo): the reviewed build-push
 * step's digest output, checked as sha256:<64 hex>, and proven to be the image this job built and pushed (G15a-R11 r5-1) before it is written
 * to the service's digest artifact folder (uploaded next, and read by the sign job and, by run id, the verify job).
 * Why the proof: on the docker driver with the classic image store, buildx pushes through the daemon and then asks the REGISTRY what the tag
 * names to fill `digest`; anyone who can write to the package could move the tag in between, and pipegen would sign their image. So the step
 * asks the daemon for its own record of the image the build made (by the build's `imageid`, never by the tag): its RepoDigests must hold
 * exactly `<imageRepo>@<digest>`. The daemon computes that entry from the manifest it pushed. Classic store: imageid is the config digest and
 * RepoDigests gets the pushed manifest; containerd store: imageid is the manifest (or index) digest itself, also in RepoDigests. Checked live
 * on both stores (G15a round 11); which store GitHub's hosted runners use is a G16 live item.
 */
export function renderPublishDigestStep(service: string, imageRepo: string): RenderedStep {
  const artifact = artifactOf(service);
  if (typeof imageRepo !== 'string' || !IMAGE_REPO_RE.test(imageRepo) || imageRepo.length > 255) throw new RenderError(`The published image repository ${show(String(imageRepo))} is not pipegen's plain ghcr.io form, so its digest can not be checked.`);
  return pipegenScriptStep(PUBLISH_DIGEST_STEP_ID, `pipegen: the digest of the published image of ${slug(service)}`, [
    'digest="$PIPEGEN_IMAGE_DIGEST"',
    'image_id="$PIPEGEN_IMAGE_ID"',
    'if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image build gave no sha256:<64 hex> digest"; fi',
    'if ! [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image build gave no sha256:<64 hex> image id"; fi',
    'for t in docker jq; do command -v "$t" > /dev/null || pg_fail "this runner has no $t, which pipegen\'s publish digest check needs"; done',
    `want=${q(imageRepo)}"@$digest"`,
    `repo_digests="$(docker image inspect --format '{{json .RepoDigests}}' -- "$image_id")" || pg_fail "the Docker daemon has no record of the image this job built, so the digest of what it pushed can not be proven"`,
    'if ! printf \'%s\' "$repo_digests" | jq -e --arg want "$want" \'type == "array" and any(.[]; . == $want)\' > /dev/null; then pg_fail "the digest the build reported is not the image this job built and pushed (the Docker daemon\'s record of that image does not hold $want): the tag may have been moved by another writer after the push, so nothing is handed on to be signed"; fi',
    `dir="$RUNNER_TEMP/pipegen-out/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-out"',
    'mkdir "$dir"',
    `printf '%s' "$digest" > "$dir/${DIGEST_FILE}"`,
  ], { ...PUBLISH_DIGEST_ENV });
}
