// v0.2 Plan G G7 (rulings B3 a, c; carries G1→G7 deploy order, G2→G7 digest download by run id, G2 order exception for the digest
// upload): pipegen's own fixed steps of the deploy layer, each one renderer shared by the builders (src/layers) and the referee, which
// recognises them only by their exact content (like the pr-check lookup and the image hand-off).
// - image-publish (job `image-publish` only): after the reviewed build-push step (`id: pipegen-build-push`, push true), the publish digest
//   step writes the pushed image's digest, checked as sha256:<64 hex>, to `$RUNNER_TEMP/pipegen-out/<digest artifact>/digest`; the folder is
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

/** The one expression each step's env holds, exactly (job-rules.ts checkExpressions accepts these and nothing else for these ids). */
export const HEAD_CHECK_ENV: Readonly<Record<string, string>> = Object.freeze({ PIPEGEN_HEAD_TOKEN: '${{ github.token }}' });
export const DIGEST_STEP_ENV: Readonly<Record<string, string>> = Object.freeze({
  PIPEGEN_RUN_ID: `\${{ steps.${FIND_RUN_STEP_ID}.outputs.run-id }}`, PIPEGEN_DIGEST_TOKEN: '${{ github.token }}',
});
export const PUBLISH_DIGEST_ENV: Readonly<Record<string, string>> = Object.freeze({ PIPEGEN_IMAGE_DIGEST: `\${{ steps.${BUILD_PUSH_STEP_ID}.outputs.digest }}` });

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
const CURL = "curl -fsS --proto '=https' --max-time 60 -H \"Authorization: Bearer $TOKEN\" -H 'Accept: application/vnd.github+json'";

/**
 * The head check of the verify job (carry G1→G7): this run is a push to the default branch, and the deployed commit (GITHUB_SHA, the
 * commit find-run proved) is still the head of that branch when the check runs, after find-run's wait. Otherwise the deploy is refused: a
 * newer commit is on the branch, and its own run deploys it (an older commit never deploys after a newer one). The job's token reads the ref.
 */
export function renderHeadCheckStep(defaultBranch: string): RenderedStep {
  const branch = branchOf(defaultBranch);
  return pipegenScriptStep(HEAD_CHECK_STEP_ID, 'pipegen: the deployed commit is the head of the default branch', [
    `want=${q(branch)}`,
    'if [ "$GITHUB_REF" != "refs/heads/$want" ]; then pg_fail "this deploy is not a push to the default branch, so it is not verified"; fi',
    'if ! [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]; then pg_fail "the deployed commit is not a 40-character commit"; fi',
    'TOKEN="$PIPEGEN_HEAD_TOKEN"',
    'unset PIPEGEN_HEAD_TOKEN',
    `head="$(${CURL} "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/git/ref/heads/$want" | jq -er 'if .object.type == "commit" and (.object.sha | type) == "string" then .object.sha else error("not a branch head") end')"`,
    'if [ "$head" != "$GITHUB_SHA" ]; then pg_fail "the default branch has moved on to a newer commit, so this older commit is not deployed (the newer commit\'s own run deploys it)"; fi',
  ], { ...HEAD_CHECK_ENV });
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
    `if [ "$(printf '%s' "$list" | jq -r '.artifacts[0].expired')" != "false" ]; then pg_fail "the gated run's image digest has expired (the run is past the artifact retention period); push to the default branch again to deploy"; fi`,
    `dir="$RUNNER_TEMP/pipegen-out/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-out"',
    'mkdir "$dir"',
    'zip="$(mktemp "$RUNNER_TEMP/pipegen-digest.XXXXXX")"',
    `${CURL.replace("--proto '=https'", "--proto '=https' --proto-redir '=https' -L --max-filesize 65536")} "$api/actions/artifacts/$id/zip" -o "$zip"`,
    'unset TOKEN',
    `unzip -p -- "$zip" ${q(DIGEST_FILE)} | head -c 100 > "$dir/${DIGEST_FILE}"`,
    'rm -f -- "$zip"',
    `digest="$(cat -- "$dir/${DIGEST_FILE}")"`,
    'if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image digest of the gated run is not sha256:<64 hex>"; fi',
    'echo "digest=$digest" >> "$GITHUB_OUTPUT"',
  ], { ...DIGEST_STEP_ENV });
}

/**
 * The publish digest step of image-publish for the image of `service`: the reviewed build-push step's digest output, checked as
 * sha256:<64 hex>, written to the service's digest artifact folder (uploaded next, and read by the sign job and, by run id, the verify job).
 */
export function renderPublishDigestStep(service: string): RenderedStep {
  const artifact = artifactOf(service);
  return pipegenScriptStep(PUBLISH_DIGEST_STEP_ID, `pipegen: the digest of the published image of ${slug(service)}`, [
    'digest="$PIPEGEN_IMAGE_DIGEST"',
    'if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image build gave no sha256:<64 hex> digest"; fi',
    `dir="$RUNNER_TEMP/pipegen-out/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-out"',
    'mkdir "$dir"',
    `printf '%s' "$digest" > "$dir/${DIGEST_FILE}"`,
  ], { ...PUBLISH_DIGEST_ENV });
}

/** Whether a step has a field set that pipegen never sets on its own run steps (a condition, continue-on-error, a time limit, a folder). */
const extra = (s: RenderedStep): boolean => s.if !== undefined || s['continue-on-error'] !== undefined || s['timeout-minutes'] !== undefined || s['working-directory'] !== undefined;
/** Whether a step is exactly this render (every field that runs; the name aside). */
export function sameRunStep(s: RenderedStep, want: RenderedStep): boolean {
  if (extra(s)) return false;
  const runs = (x: RenderedStep): unknown[] => [x.id, x.uses, x.with, x.run, x.shell, x.env];
  return JSON.stringify(runs(s)) === JSON.stringify(runs(want));
}
