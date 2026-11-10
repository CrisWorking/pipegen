// v0.2 Plan G, sub-task G2 (ruling B6, option 3; carries BF-B1, G16, C-MUST-1): the PR's own image, scanned without a registry write.
// - `image-build--<svc>` (repo code, contents: read, no secret): the reviewed build-push action builds the service's Dockerfile with no push
//   (the default docker builder keeps the image in the runner's image store, under a local tag), then pipegen's archive step saves exactly
//   that tag to `image.tar`, writes its sha256 as a step output (the job output `image-sha256`), and the archive folder is uploaded as
//   `pipegen-out-image-archive--<svc>`. That tail (archive, upload) right after the build is the one exception to the order rule (job-rules.ts):
//   the build runs inside BuildKit's containers, not on the runner, and the sha256 binds the archive to this job.
// - the scanner job (trivy-image, syft): downloads the archive, checks its sha256 against `needs.image-build--<svc>.outputs.image-sha256`
//   BEFORE anything reads it, then scans it with `--input` (trivy) or `docker-archive:` (syft). The scan step is the reviewed tool's own
//   rendered step with its image target replaced by the archive (one transform, used by the renderer and the referee alike).
// - No base twin of an archive scan exists (B6: there is no base build yet); the gate reads "couldn't run on the base".
import { slug } from './artifact-names.js';
import {
  IMAGE_ARCHIVE_FILE, IMAGE_ARCHIVE_STEP_ID, IMAGE_SHA_ENV, IMAGE_SHA_OUTPUT, imageArchiveArtifact, imageCheckStepId, imageShaRef, stepOutputForm, type RenderedStep,
} from './job-rules.js';
import type { PlatformActions } from './pin.js';
import { pipegenScriptStep } from './pipegen-script.js';
import { RenderError, show } from './render-error.js';
import { renderPlatformStep, renderStep, type RenderContext, type RenderResult } from './render-step.js';
import type { CreatedFile, RepoProfile, ReviewedTool, StepSpec } from '../types.js';

export { imageArchiveArtifact, IMAGE_ARCHIVE_FILE, IMAGE_SHA_OUTPUT };

/** The local tag the build gives the image and the archive step saves (never pushed: no registry, so no one else's image can answer to it). */
/**
 * G17B-R0 (row 19): the profile the image renderers read. A service with no Dockerfile of its own gets the one pipegen creates in the same
 * draft at its folder (`<folder>/Dockerfile`, part docker, app repository; the referee's Dockerfile judge holds its text), so its image build,
 * its image scans and its DAST archive start render from it. Shared by the assembler, the DAST start and the referee: one source.
 */
export function imageProfile(profile: RepoProfile, created: readonly CreatedFile[] | undefined): RepoProfile {
  const made = new Set((Array.isArray(created) ? created : []).filter((f) => f !== null && typeof f === 'object' && f.repo === 'app' && f.part === 'docker' && typeof f.path === 'string' && /(?:^|\/)Dockerfile$/.test(f.path)).map((f) => f.path));
  if (made.size === 0) return profile;
  let changed = false;
  const services = profile.services.map((svc) => {
    if ((svc.dockerfile ?? '') !== '' || typeof svc.path !== 'string') return svc;
    const dir = svc.path === '.' ? '' : svc.path.replace(/^\.\//, '').replace(/\/+$/, '');
    const at = dir === '' ? 'Dockerfile' : `${dir}/Dockerfile`;
    if (!made.has(at)) return svc;
    changed = true;
    return { ...svc, dockerfile: at };
  });
  return changed ? { ...profile, services } : profile;
}

export const imageBuildTag = (service: string): string => `pipegen-image/${slug(service)}:build`;
/** The archive in the job's runner temp, as a shell word (the run steps name it; never an env value, which Actions would not expand). */
const archivePath = (service: string): string => `$RUNNER_TEMP/pipegen-out/${imageArchiveArtifact(service)}/${IMAGE_ARCHIVE_FILE}`;
const bash = pipegenScriptStep;

/** The service of a spec, with a slug (an image is per service). */
function serviceOf(spec: StepSpec, ctx: RenderContext): string {
  const name = spec.service;
  if (name === undefined || !ctx.profile.services.some((s) => s.name === name)) throw new RenderError('An image build or scan belongs to one service of this repository.');
  slug(name);
  return name;
}

/** The archive step of a service's image-build job: saves the built tag, checks the file and writes its sha256 (the job output image-sha256). */
export function renderImageArchiveStep(service: string): RenderedStep {
  const artifact = imageArchiveArtifact(service);
  return bash(IMAGE_ARCHIVE_STEP_ID, `Save the image of ${slug(service)} as an archive`, [
    `dir="$RUNNER_TEMP/pipegen-out/${artifact}"`,
    'mkdir -p "$RUNNER_TEMP/pipegen-out"',
    'mkdir "$dir"',
    `/usr/bin/docker image save --output "$dir/${IMAGE_ARCHIVE_FILE}" '${imageBuildTag(service)}'`,
    `if [ ! -f "$dir/${IMAGE_ARCHIVE_FILE}" ] || [ -L "$dir/${IMAGE_ARCHIVE_FILE}" ]; then pg_fail "the image archive is not a regular file"; fi`,
    `sum="$(sha256sum -- "$dir/${IMAGE_ARCHIVE_FILE}" | cut -d ' ' -f 1)"`,
    'if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]]; then pg_fail "the sha256 of the image archive could not be read"; fi',
    'echo "sha256=$sum" >> "$GITHUB_OUTPUT"',
  ]);
}

/**
 * The steps of `image-build--<svc>` after its checkout: the reviewed build-push step (push false, the service's Dockerfile, the local tag),
 * the archive step and the upload of the archive folder; and the job outputs (`image-sha256`). A spec that asks to push, a service in a
 * sub-folder (the template's context is the repository root, ruling S8) or a service with no Dockerfile is a RenderError.
 */
export function renderImageBuild(spec: StepSpec, buildPush: ReviewedTool, platform: PlatformActions, ctx: RenderContext): { steps: RenderedStep[]; outputs: Record<string, string> } {
  if (spec.needId !== 'image-build') throw new RenderError(`An image build renders the image-build check, not ${show(spec.needId)}.`);
  const service = serviceOf(spec, ctx);
  const svc = ctx.profile.services.find((s) => s.name === service);
  if (svc?.dockerfile === undefined || svc.dockerfile === '') throw new RenderError(`The service ${show(service)} has no Dockerfile to build.`);
  if (spec.choices.push !== undefined && spec.choices.push !== 'false') throw new RenderError('An image build for a check never pushes (B6): the scanners get the image as an archive.');
  // a build for a check is always blocking-safe: push false, whatever the need says
  const build = renderStep({ ...spec, choices: { ...spec.choices, push: 'false' } }, buildPush, platform, { ...ctx, targets: { ...ctx.targets, image: imageBuildTag(service) }, blocking: true }).steps;
  if (build.length !== 1 || build[0]?.with?.push !== 'false' || build[0].with.file !== svc.dockerfile || build[0].with.tags !== imageBuildTag(service)) {
    throw new RenderError(`The build step of ${show(service)} is not the reviewed build-push step with no push, its Dockerfile and its local tag.`);
  }
  const artifact = imageArchiveArtifact(service);
  const upload = { ...renderPlatformStep('upload-artifact', platform, { name: artifact, path: `\${{ runner.temp }}/pipegen-out/${artifact}` }), name: `Upload the image archive of ${slug(service)}` };
  return { steps: [build[0] as RenderedStep, renderImageArchiveStep(service), upload], outputs: { [IMAGE_SHA_OUTPUT]: stepOutputForm(IMAGE_ARCHIVE_STEP_ID, 'sha256') } };
}

/** The scanner job's hash check: the downloaded archive must have exactly the sha256 its image-build job wrote, before anything reads it. */
export function renderImageCheckStep(service: string): RenderedStep {
  return bash(imageCheckStepId(service), `Check the image archive of ${slug(service)}`, [
    `file="${archivePath(service)}"`,
    `if ! [[ "$${IMAGE_SHA_ENV}" =~ ^[0-9a-f]{64}$ ]]; then pg_fail "the image build gave no sha256 for its archive"; fi`,
    'if [ ! -f "$file" ] || [ -L "$file" ]; then pg_fail "the image archive is missing or not a regular file"; fi',
    `printf '%s  %s\\n' "$${IMAGE_SHA_ENV}" "$file" | sha256sum --check --strict - > /dev/null || pg_fail "the image archive is not the one the image build made (sha256 differs)"`,
  ], { [IMAGE_SHA_ENV]: imageShaRef(slug(service)) });
}

/** The image tools that read an archive, and how each names it in place of the image reference. */
export const ARCHIVE_WORD: Readonly<Record<string, (path: string) => string>> = Object.freeze({
  'trivy-image': (path: string) => `--input "${path}"`,
  syft: (path: string) => `"docker-archive:${path}"`,
});
/** The ids of the image tools that read an archive (the referee's list, one source). */
export const ARCHIVE_TOOL_IDS: ReadonlySet<string> = new Set(Object.keys(ARCHIVE_WORD));
/** The image the transform renders with and replaces: a name no registry serves, so a left-over could never scan a real image. */
const ARCHIVE_SENTINEL = `ghcr.io/pipegen-archive/sentinel@sha256:${'0'.repeat(64)}`;
const count = (text: string, part: string): number => text.split(part).length - 1;

/**
 * A scanner of the PR's own image, on its archive: the download of the archive, the hash check, then the reviewed tool's rendered steps
 * with the image target replaced by the archive. Throws a RenderError for a tool that reads no archive, a spec with problems (a narrowing
 * choice for a blocking need included), or a render whose image word is not exactly where the transform expects it.
 */
export function renderImageArchiveScan(spec: StepSpec, tool: ReviewedTool, platform: PlatformActions, ctx: RenderContext): RenderResult {
  const word = Object.hasOwn(ARCHIVE_WORD, tool.id) ? ARCHIVE_WORD[tool.id] : undefined;
  if (word === undefined) throw new RenderError(`${show(tool.id)} does not scan an image archive.`);
  if (ctx.base === true) throw new RenderError('An archive scan has no base twin: there is no base build yet (B6).');
  const service = serviceOf(spec, ctx);
  const r = renderStep(spec, tool, platform, { ...ctx, targets: { ...ctx.targets, image: ARCHIVE_SENTINEL } });
  const last = r.steps.length - 1;
  const scan = r.steps[last];
  const keys = Object.entries(scan?.env ?? {}).filter(([, v]) => v === ARCHIVE_SENTINEL).map(([k]) => k);
  const run = scan?.run;
  const k = keys[0];
  if (scan === undefined || run === undefined || keys.length !== 1 || k === undefined || !/^PIPEGEN_ARG_\d{1,2}$/.test(k)
    || r.steps.slice(0, last).some((s) => JSON.stringify(s).includes(ARCHIVE_SENTINEL))) {
    throw new RenderError(`The render of ${show(tool.id)} does not take its image in exactly one place, so it can not read an archive.`);
  }
  const allow = `\n  "${k}=$${k}"`;
  const use = ` "$${k}"`;
  if (count(run, allow) !== 1 || count(run, use) !== 1 || count(run, `$${k}`) !== 2) throw new RenderError(`The run of ${show(tool.id)} does not use its image word exactly once, so it can not read an archive.`);
  const env = Object.fromEntries(Object.entries(scan.env ?? {}).filter(([n]) => n !== k));
  const read: RenderedStep = { ...scan, run: run.replace(allow, '').replace(use, ` ${word(archivePath(service))}`), env };
  const artifact = imageArchiveArtifact(service);
  const download = renderPlatformStep('download-artifact', platform, { name: artifact, path: `\${{ runner.temp }}/pipegen-out/${artifact}` });
  return { ...r, steps: [{ ...download, name: `Download the image archive of ${slug(service)}` }, renderImageCheckStep(service), ...r.steps.slice(0, last), read] };
}
