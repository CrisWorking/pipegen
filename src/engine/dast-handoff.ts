// v0.2 Plan G G4 fix round 1 (ruling G4-R1, the reviewer's design A): DAST in two jobs, one renderer for the assembler and the referee.
// - `dast-run--<svc>` (contents: read, no key, no secret, no token): the app starts in containers only, either from pipegen's own compose file
//   (the runtime env, then compose up: its app services are built from their Dockerfile and published on 127.0.0.1) or from the service's image
//   archive (downloaded, checked against the image build's sha256, `docker load`ed and run with no capability, no privilege gain, no mount and
//   no env, published on 127.0.0.1 only). Then the reviewed DAST step against http://127.0.0.1:<port>, and the hand-off: the app must still
//   answer (C1a: a scanner can exit 0 against a dead target), the raw result is copied to its hand-off folder and its sha256 becomes the job
//   output `raw-sha256`; then the upload of that folder. The order rule's one exception for this tail is job-rules.ts dastRunTailAt.
// - `dast--<svc>` (the gate's job id): the download of the raw result, its sha256 check against the run job's output BEFORE anything reads it
//   (the copy into the raw folder the scrub reads), the scrub (the fingerprint key, here only), the upload of the scrubbed result.
// - No base twin: the base commit's app is not started (C-MUST-1); the gate reads "couldn't run on the base".
// Residual (PIPEGEN.md): the raw result is uploaded unscrubbed between the two jobs of one run; it holds only what an app with no secret
// answered. A hostile app can always answer a scanner cleanly: DAST finds honest mistakes, it does not judge a hostile pull request.
import { servicesByName } from './names.js';
import { planCompose, COMPOSE_PATH } from '../create/compose.js';
import type { PipelineDraft, ReviewedTool, RuntimeEnv, StepSpec } from '../types.js';
import { slug } from './artifact-names.js';
import { loadBaseImages, type BaseImage } from './base-images.js';
import { dockerfilesOf } from './created-judges/compose.js';
import { imageBuildTag, imageProfile, renderImageCheckStep } from './image-handoff.js';
import {
  DAST_HANDOFF_STEP_ID, DAST_RAW_SHA_ENV, DAST_RAW_SHA_OUTPUT, dastAppStepId, dastCheckStepId, dastLaneOf, dastRawArtifact, dastRawShaRef, dastResultArtifact, ZAP_ACTIVE_LANE, type DastLane,
  IMAGE_ARCHIVE_FILE, imageArchiveArtifact, imageBuildJobId, IMAGE_BUILD_NEED, stepOutputForm, type RenderedStep, type ScanFact,
} from './job-rules.js';
import { PLATFORM_ACTION_IDS, type PlatformActions } from './pin.js';
import { pipegenScriptStep } from './pipegen-script.js';
import { RenderError } from './render-error.js';
import { renderComposeUp, renderPlatformStep, renderRuntimeEnv, renderScrub, renderStep, renderUpload, scrubbedPath, type RenderResult } from './render-step.js';

/**
 * G15a round 4 (b3, P-4): the nightly DAST tool. Nuclei 3.11.1 with its pinned templates: its result is SARIF, and the gate's nuclei reader
 * was checked against a real run of the pinned binary (test/fixtures/sarif/nuclei.sarif).
 */
export const NIGHTLY_DAST_TOOL = 'nuclei';
/**
 * G15a round 6 (P-4): the nightly ZAP Automation Framework active scan, beside nuclei, in its own lane (job-rules.ts ZAP_ACTIVE_LANE): the
 * reviewed entry `zap-af-active` (the pinned zap-stable image) with pipegen's reviewed plan (zap-active.ts). Its report was captured from
 * the pinned image and is read by the gate's ZAP reader (gate/src/zap.ts ZAP_AF_TOOL); the scrub writes it as SARIF for code scanning.
 */
export const ZAP_ACTIVE_TOOL = 'zap-af-active';
export { ZAP_ACTIVE_LANE };
/**
 * The AF run job's timeout: the plan may take 5 minutes of spider, 5 of passive wait and 30 of active scan (zap-active.ts), on top of the
 * pull of the ZAP image and the app start; the default 30 would cancel a scan that ran to its limits.
 */
export const ZAP_ACTIVE_JOB_MINUTES = 60;
/** The note when the AF scan can not be written (the entry is missing, or its render is refused): nuclei still runs. */
export const zapActiveNotRunNote = (why: string): string => `ZAP's active scan is not run nightly: ${why} Nuclei scans the app nightly instead.`;

/**
 * The nightly DAST spec of a merge-layer DAST check: the same check and service, run by the reviewed nuclei entry with nothing chosen (no AI
 * value reaches it). Shared by the assembler and the referee, so both render the same steps.
 */
export function nightlyDastSpec(spec: StepSpec, nuclei: ReviewedTool): StepSpec {
  if (typeof spec.service !== 'string') throw new RenderError('A DAST check belongs to one service.');
  if (nuclei.id !== NIGHTLY_DAST_TOOL || nuclei.candidate.id !== NIGHTLY_DAST_TOOL) throw new RenderError('The nightly DAST scan runs only the reviewed nuclei entry.');
  return { needId: spec.needId, service: spec.service, tool: nuclei.candidate, choices: {}, output: nuclei.step.output };
}

/**
 * G15a round 6: the nightly ZAP AF spec of a merge-layer DAST check: the same service, in the zap-active lane (its need id, so its artifacts
 * and jobs are the lane's), run by the reviewed AF entry with nothing chosen. Shared by the assembler and the referee.
 */
export function zapActiveSpec(spec: StepSpec, af: ReviewedTool): StepSpec {
  if (typeof spec.service !== 'string') throw new RenderError('A DAST check belongs to one service.');
  if (af.id !== ZAP_ACTIVE_TOOL || af.candidate.id !== ZAP_ACTIVE_TOOL) throw new RenderError("The nightly ZAP active scan runs only the reviewed ZAP AF entry.");
  return { needId: ZAP_ACTIVE_LANE, service: spec.service, tool: af.candidate, choices: {}, output: af.step.output };
}

/** The render context options of a DAST spec's lane: the AF lane renders as pipegen's own nightly scan (a nightly-only entry needs it). */
const laneCtx = (lane: DastLane): { nightly?: true } => (lane === ZAP_ACTIVE_LANE ? { nightly: true } : {});

/** Why a DAST step may name no secret (G17 row 14): the assembler's refusal and the renderer's. */
export const DAST_SECRETS_REASON = 'A DAST check runs the app with no secret: the scanner and the app it starts in a container get none, so pipegen never passes one to it.';

/** Where the app runs for the DAST check of one service: pipegen's compose file, or the image archive; the port it is published on. */
export type DastStart = { kind: 'compose'; port: number; url: string; env: RuntimeEnv } | { kind: 'archive'; port: number; url: string };

const validPort = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= 65535;

/**
 * How the app of `service` starts for its DAST check, or why it can not (a plain reason): pipegen's compose file when the draft holds exactly
 * the file pipegen computes and the service is one of its apps; else the image archive when the draft builds the service's image (a
 * renderable image-build step) and the service has a port. Shared by the assembler and the referee, so both render the same steps.
 */
export function dastStartOf(draft: PipelineDraft, service: string, baseImages: readonly BaseImage[] = loadBaseImages()): DastStart | { problem: string } {
  const svc = servicesByName(draft.profile).get(service);
  if (svc === undefined) return { problem: 'it is not a service pipegen found' };
  const file = draft.created.find((f) => f.repo === 'app' && f.path === COMPOSE_PATH);
  if (file !== undefined) {
    const plan = planCompose(draft.profile, baseImages, dockerfilesOf(draft.created));
    const app = plan.apps.find((a) => a.service === service);
    if (plan.text !== null && plan.text === file.content && app !== undefined && validPort(app.port)) return { kind: 'compose', port: app.port, url: `http://127.0.0.1:${app.port}`, env: plan.env };
  }
  const build = draft.steps.find((s) => s.needId === IMAGE_BUILD_NEED && s.service === service && s.tool.id === PLATFORM_ACTION_IDS['build-push']);
  // G17B-R0: a Dockerfile pipegen creates in this draft counts (imageProfile, the image build's own source)
  const dockerfile = servicesByName(imageProfile(draft.profile, draft.created)).get(service)?.dockerfile;
  if (build === undefined || (dockerfile ?? '') === '') return { problem: 'it has no container image pipegen builds (a Dockerfile it builds, or pipegen\'s compose file), and pipegen starts the app for a scan in a container only' };
  if (!validPort(svc.port)) return { problem: 'pipegen found no port the app listens on, so there is nothing to scan' };
  return { kind: 'archive', port: svc.port, url: `http://127.0.0.1:${svc.port}` };
}

/** The archive start step: load the checked archive, run its image bound to 127.0.0.1 with no capability, wait until it answers. */
export function renderDastAppStart(service: string, port: number): RenderedStep {
  if (!validPort(port)) throw new RenderError('The DAST target has no valid port.');
  const s = slug(service);
  const tag = imageBuildTag(service);
  const ctr = `pipegen-dast-${s}`;
  return pipegenScriptStep(dastAppStepId(service), `Start ${s} from its checked image (container only, 127.0.0.1:${port})`, [
    `file="$RUNNER_TEMP/pipegen-out/${imageArchiveArtifact(service)}/${IMAGE_ARCHIVE_FILE}"`,
    'if [ ! -f "$file" ] || [ -L "$file" ]; then pg_fail "the image archive is missing or not a regular file"; fi',
    'loaded="$(/usr/bin/docker load --input "$file")"',
    `case "$loaded" in *"Loaded image: ${tag}"*) ;; *) pg_fail "the archive does not hold the image of ${s}" ;; esac`,
    `/usr/bin/docker rm -f ${ctr} > /dev/null 2>&1 || true`,
    `/usr/bin/docker run --detach --name ${ctr} --pull=never --cap-drop ALL --security-opt no-new-privileges --publish 127.0.0.1:${port}:${port} '${tag}' > /dev/null`,
    'for i in $(seq 1 30); do',
    `  if /usr/bin/curl --silent --max-time 5 --output /dev/null http://127.0.0.1:${port}/; then exit 0; fi`,
    '  sleep 2',
    'done',
    `/usr/bin/docker logs --tail 100 ${ctr} || true`,
    `pg_fail "the app did not answer on 127.0.0.1:${port}"`,
  ]);
}

/** The raw result file of a DAST render (its path and name), checked. */
function rawOf(r: RenderResult, service: string, lane: DastLane): { path: string; file: string; format: 'sarif' | 'zap-json' } {
  const out = r.output;
  const artifact = dastResultArtifact(service, lane);
  const prefix = `\${{ runner.temp }}/pipegen-raw/${artifact}/`;
  if (out === null || !out.path.startsWith(prefix) || (out.format !== 'sarif' && out.format !== 'zap-json')) throw new RenderError('The DAST step writes no findings file in its own raw folder.');
  const file = out.path.slice(prefix.length);
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/.test(file)) throw new RenderError('The DAST result file has no plain name.');
  return { path: out.path, file, format: out.format };
}

/** The hand-off step: the app still answers (C1a), then the raw result is copied to its hand-off folder and its sha256 written as the job output. */
export function renderDastHandoffStep(service: string, file: string, url: string, lane: DastLane = 'dast'): RenderedStep {
  const raw = dastRawArtifact(service, lane);
  return pipegenScriptStep(DAST_HANDOFF_STEP_ID, `Hand the raw scan result of ${slug(service)} on`, [
    `code="$(/usr/bin/curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' ${url}/ || true)"`,
    'case "$code" in [1-4][0-9][0-9]) ;; *) pg_fail "the app no longer answers after the scan (HTTP $code), so the scan can not be shown to have reached it" ;; esac',
    `src="$RUNNER_TEMP/pipegen-raw/${dastResultArtifact(service, lane)}/${file}"`,
    'if [ ! -f "$src" ] || [ -L "$src" ]; then pg_fail "the scan left no regular result file"; fi',
    `dir="$RUNNER_TEMP/pipegen-out/${raw}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-out"',
    'mkdir "$dir"',
    `cp -- "$src" "$dir/${file}"`,
    `sum="$(sha256sum -- "$dir/${file}" | cut -d ' ' -f 1)"`,
    'if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]]; then pg_fail "the sha256 of the raw result could not be read"; fi',
    'echo "sha256=$sum" >> "$GITHUB_OUTPUT"',
  ]);
}

/** The scrub job's hash check: the downloaded raw result must be the one the run job handed on, then it goes to the raw folder the scrub reads. */
export function renderDastCheckStep(service: string, file: string, lane: DastLane = 'dast'): RenderedStep {
  const raw = dastRawArtifact(service, lane);
  const artifact = dastResultArtifact(service, lane);
  return pipegenScriptStep(dastCheckStepId(service, lane), `Check the raw scan result of ${slug(service)}`, [
    `src="$RUNNER_TEMP/pipegen-out/${raw}/${file}"`,
    `if ! [[ "$${DAST_RAW_SHA_ENV}" =~ ^[0-9a-f]{64}$ ]]; then pg_fail "the DAST run gave no sha256 for its raw result"; fi`,
    'if [ ! -f "$src" ] || [ -L "$src" ]; then pg_fail "the raw scan result is missing or not a regular file"; fi',
    `printf '%s  %s\\n' "$${DAST_RAW_SHA_ENV}" "$src" | sha256sum --check --strict - > /dev/null || pg_fail "the raw scan result is not the one the DAST run made (sha256 differs)"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-raw"',
    `mkdir "$RUNNER_TEMP/pipegen-raw/${artifact}"`,
    `cp -- "$src" "$RUNNER_TEMP/pipegen-raw/${artifact}/${file}"`,
    `chmod -R a-w "$RUNNER_TEMP/pipegen-raw/${artifact}"`,
  ], { [DAST_RAW_SHA_ENV]: dastRawShaRef(slug(service), lane) });
}

/**
 * The steps of `dast-run--<svc>` after its egress step: the app start (compose, or the archive download, its hash check and the start step),
 * the reviewed DAST step's own steps against the local URL, the hand-off and the upload; its outputs and needs. `checkout` is the prelude a
 * compose start needs (its build context); the archive start needs none.
 */
export function renderDastRun(spec: StepSpec, tool: ReviewedTool, platform: PlatformActions, draft: PipelineDraft, start: DastStart, opts: { blocking: boolean; checkout: readonly RenderedStep[] }): { steps: RenderedStep[]; outputs: Record<string, string>; needs: string[]; scan: RenderedStep[] } {
  const service = spec.service;
  if (service === undefined) throw new RenderError('A DAST check belongs to one service.');
  // G17 row 14: the run job holds no secret (dastRunTailAt refuses one); refused here first, whatever the tool's categories say
  if (Array.isArray(spec.secrets) && spec.secrets.length > 0) throw new RenderError(DAST_SECRETS_REASON);
  const lane = dastLaneOf(spec.needId);
  const r = renderStep(spec, tool, platform, { profile: draft.profile, targets: { url: start.url }, blocking: opts.blocking, ...laneCtx(lane) });
  const raw = rawOf(r, service, lane);
  const startSteps: RenderedStep[] = start.kind === 'compose'
    ? [...opts.checkout, renderRuntimeEnv(start.env), renderComposeUp()]
    : [{ ...renderPlatformStep('download-artifact', platform, { name: imageArchiveArtifact(service), path: `\${{ runner.temp }}/pipegen-out/${imageArchiveArtifact(service)}` }), name: `Download the image archive of ${slug(service)}` },
      renderImageCheckStep(service), renderDastAppStart(service, start.port)];
  const rawName = dastRawArtifact(service, lane);
  const upload = { ...renderPlatformStep('upload-artifact', platform, { name: rawName, path: `\${{ runner.temp }}/pipegen-out/${rawName}` }), name: `Upload the raw scan result of ${slug(service)}` };
  return {
    steps: [...startSteps, ...r.steps, renderDastHandoffStep(service, raw.file, start.url, lane), upload],
    outputs: { [DAST_RAW_SHA_OUTPUT]: stepOutputForm(DAST_HANDOFF_STEP_ID, 'sha256') },
    needs: start.kind === 'archive' ? [imageBuildJobId(service)] : [],
    scan: r.steps,
  };
}

/** The steps of `dast--<svc>` after its egress step: the download of the raw result, its hash check, the scrub and the upload; and its scan fact. */
export function renderDastScrub(spec: StepSpec, tool: ReviewedTool, platform: PlatformActions, draft: PipelineDraft, gate: ReviewedTool, url: string): { steps: RenderedStep[]; scan: { stepId: string; fact: ScanFact } } {
  const service = spec.service;
  if (service === undefined) throw new RenderError('A DAST check belongs to one service.');
  const lane = dastLaneOf(spec.needId);
  const raw = rawOf(renderStep(spec, tool, platform, { profile: draft.profile, targets: { url }, ...laneCtx(lane) }), service, lane);
  const rawName = dastRawArtifact(service, lane);
  const artifact = dastResultArtifact(service, lane);
  const download = { ...renderPlatformStep('download-artifact', platform, { name: rawName, path: `\${{ runner.temp }}/pipegen-out/${rawName}` }), name: `Download the raw scan result of ${slug(service)}` };
  const check = renderDastCheckStep(service, raw.file, lane);
  return {
    steps: [download, check, renderScrub(artifact, raw.path, tool.id, raw.format, gate), renderUpload(artifact, scrubbedPath(raw.path), platform)],
    scan: { stepId: check.id as string, fact: { tool: tool.id, format: raw.format } },
  };
}

