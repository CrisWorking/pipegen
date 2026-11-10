// Plan E Task 2, second half / sub-task E3 (spec §11, §19; rulings B5, B7, S6, S17, E3-R1, E2 r1-m3; threats T21, T22, T32):
// what a proof runs besides pipegen's own workflows. The scratch repo holds the user's real test keys during the proof, so
// every job here starts with the reviewed egress step, holds no literal secret, and has no trigger a person or API call
// can start (no workflow_dispatch).
//
// - The proof harness (harnessWorkflow): `.github/workflows/pipegen-proof-harness.yml`, scratch only, never delivered and
//   never refereed. Triggers: pull_request and push, both to the default branch only. Jobs:
//   - egress-check (both events): the egress step, then renderEgressCheckStep (a request to a host that isn't allowed must
//     fail: catches an egress tool that fails open, as Harden-Runner did on a private repo, S8). Its job and step env hold
//     no BASH_ENV or ENV (E0d review).
//   - app-start (pull_request; ruling B7): egress (the apps' package registry, dockerhub, docker networks) → checkout →
//     renderRuntimeEnv → `docker build --network host` per app service from its own folder → the computed compose override
//     (image: per app service only) → renderComposeUp({ proofOverride }) with --no-build → a probe per app (started = an
//     HTTP status below 500). Only when the draft's compose file is the one pipegen computes.
//   - sign-roundtrip (pull_request; only when the delivered signing mode is not `none`): the reviewed `registry` image as a
//     job service on 127.0.0.1:5000, the reviewed cosign, a throwaway key pair made in the job, build → push → sign
//     key-based with --tlog-upload=false (and --use-signing-config=false, which cosign 3 needs for it) → verify with
//     --insecure-ignore-tlog. No Sigstore host, nothing in a public log.
//   - tests-repeat (pull_request; only when createdTests, which src/proof never sets: D7-R7, S6): the created tests a second
//     time through renderStarterTestRun (a container with --network none), JUnit uploaded as pipegen-out-junit-repeat-<svc>.
//   - verify-lookup (push only, so it runs after the merge): renderFindRunStep with the layout from draft.centralPin and the
//     proof's central sha, for github.sha. Permissions contents: read, actions: read.
//   Every other job has contents: read only. Every action is the reviewed or platform entry, pinned by commit.
// - Compat copies (compatCopiesFrom / compatCopies; S17, plan Task 2): one `pipegen-compat-<file>` per user workflow of
//   HEAD that runs on push or pull_request. RE-RENDERED from the parsed model (E2 r1-m3): every string double-quoted
//   (or a block literal), no anchor, alias, tag or merge key, and it must parse back (parseYaml strict) to exactly the
//   model. Trigger pull_request only; permissions contents: read at the top and on every job; no egress step (S17: the
//   user's hosts are unknown). A job is NOT COMPARED (listed with the reason, never run with more rights) when it uses a
//   secret other than GITHUB_TOKEN, an environment, id-token or any write permission, a runner that isn't a plain
//   GitHub-hosted label (an expression, a matrix value, self-hosted, a group), a reusable workflow, a key pipegen can't
//   model, a `<owner>/pipelines` reference, when it deploys, or when it needs a job that isn't compared.
//   Ruling E3-R2: a compat copy keeps the user's own actions as the user pinned them (often by tag). The user already runs
//   them, and in the copy they get no secret, a contents: read token and their own VM. That exemption is for compat copies
//   only; a job using actions/cache is still not compared. A compat job may keep a setup-* `cache:` input (ruling E3-R5:
//   "no proof job restores a cache" means the KEY-HOLDING jobs; none of them reads any cache, so a compat job's cache
//   reaches nothing that holds keys). The compat kind is a marker set here (markCompatCopy), never a path (review-r1 m3).
// - proofAppFiles: the `appFiles(centralSha)` callback pushProofSetup (E2) takes: the injected Plan G assemble, always called
//   with signing mode `none` (no public log from the scratch repo), plus the harness and the compat copies. Every workflow of
//   them passes checkProofWorkflows (workflow-check.ts) before it is returned (review I1), central callees by shape only;
//   pushProofSetup checks again at the push seam with the central tree (review-r1 I1-r1 a, m3).
// - Known and harmless (review M5): sign-roundtrip also builds with `docker build --network host` (B7's reason, S8: the build's
//   package installs fail on the bridge network under Bullfrog). The host network is still under the job's Bullfrog list, and
//   the job maps no secret. Its job service (the reviewed registry image, pinned by digest) starts at job setup, before the
//   egress step: no repo code runs in it, and checkProofWorkflows allows a service only as a digest-pinned image without
//   options or volumes.
import { Document, isScalar, Scalar, visit, YAMLMap } from 'yaml';
import { isDeepStrictEqual } from 'node:util';
import { dockerfilesOf } from '../engine/created-judges/compose.js';
import { planCompose, COMPOSE_PATH, type ComposeApp } from '../create/compose.js';
import { slug, ArtifactNameError } from '../engine/artifact-names.js';
import { loadBaseImages, baseImageRef, nodeBaseImageId, type BaseImage } from '../engine/base-images.js';
import { egressSetsForTool, renderEgressCheckStep, renderEgressStep, type EgressSet } from '../engine/egress.js';
import { WORKFLOW_PATH_RE } from '../engine/job-rules.js';
import { parseImageRef } from '../engine/names.js';
import type { PlatformActions } from '../engine/pin.js';
import { releaseInstallStep, renderStarterTestRun } from '../engine/render-cli.js';
import { RenderError } from '../engine/render-error.js';
import { escapeLineBreaks } from '../engine/yaml-breaks.js';
import {
  PROOF_OVERRIDE_PATH, renderComposeUp, renderFindRunStep, renderJobPrelude, renderPlatformStep, renderRuntimeEnv, stepsToYaml, type RenderedStep,
} from '../engine/render-step.js';
import { loadReviewed } from '../engine/reviewed.js';
import { PLAIN_REL_RE, sha16 } from '../engine/tool-flags.js';
import { isObj, parseYaml, type Obj } from '../engine/yaml-parse.js';
import type { SigningMode } from '../github/signing-mode.js';
import { jobDeploys, namesDeploy } from '../read/workflows.js';
import type { CreatedFile, PipelineDraft, RepoProfile, ReviewedTool, Service } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { readSnapshot } from './git.js';
import { ProofStopError, validBranchName } from './target.js';
import { checkProofWorkflows, isCompatCopy, markCompatCopy, namesSecret, proofWorkflowProblems } from './workflow-check.js';

export const HARNESS_PATH = '.github/workflows/pipegen-proof-harness.yml';
export const COMPAT_PREFIX = '.github/workflows/pipegen-compat-';
export const HARNESS_JOB_IDS = Object.freeze(['egress-check', 'app-start', 'sign-roundtrip', 'tests-repeat', 'verify-lookup'] as const);
export type HarnessJobId = typeof HARNESS_JOB_IDS[number];
/** The signing mode every proof pipeline is assembled with (plan Global Constraints): no keyless signing from the scratch repo. */
export const PROOF_SIGNING_MODE = 'none' as const satisfies SigningMode;

const RUNS_ON = 'ubuntu-24.04';
const SHA_RE = /^[0-9a-f]{40}$/;
const PR_ONLY = "github.event_name == 'pull_request'";
const PUSH_ONLY = "github.event_name == 'push'";
/** find-run waits while the merge run is in progress (it holds the whole merge layer): its own limit, and the job's a little longer. */
const FIND_RUN_MINUTES = 45;
const JOB_MINUTES: Readonly<Record<HarnessJobId, number>> = Object.freeze({
  'egress-check': 5, 'app-start': 30, 'sign-roundtrip': 30, 'tests-repeat': 30, 'verify-lookup': FIND_RUN_MINUTES + 5,
});
const REGISTRY_PORT = 5000;

// ---------- the harness ----------

export interface HarnessOptions {
  platform: PlatformActions;
  /** The reviewed list (default loadReviewed()): bullfrog, registry, cosign, vitest-coverage and pipegen-gate come from it. */
  reviewed?: readonly ReviewedTool[];
  /** The proof's central draft commit (proof/<runId> of pipelines): required exactly when the draft has a central pin. */
  centralSha?: string;
  /** Created (starter) tests exist and may run: only Plan G sets it, under D7-R7. src/proof never does. */
  createdTests: boolean;
  /** The DELIVERED signing mode (signingMode(profile, caps)): sign-roundtrip is rendered only when it is not `none`. */
  signing: SigningMode;
  baseImages?: readonly BaseImage[];
}

export interface HarnessJob { id: HarnessJobId; on: 'pull_request' | 'push' | 'both'; egress: EgressSet[]; dockerNetworks: boolean }
export interface Harness {
  file: CreatedFile;
  jobs: HarnessJob[];
  /** Why a job isn't there (no compose file, no image, no created tests, signing none, ...). */
  notes: string[];
}

const tool = (list: readonly ReviewedTool[], id: string): ReviewedTool => {
  const matches = list.filter((t) => t.id === id);
  if (matches.length !== 1 || matches[0]?.candidate.source !== 'reviewed' || matches[0].candidate.reviewed !== true) throw new RenderError(`The reviewed list has no single reviewed ${id} entry.`);
  return matches[0];
};

const folderOf = (path: string): string => (path === '.' ? '' : path.replace(/^\.\//, '').replace(/\/+$/, ''));
const isPlainFolder = (path: unknown): path is string => typeof path === 'string' && (path === '' || path === '.' || PLAIN_REL_RE.test(path));

/** The package-registry sets a service's own install needs (npm → npm, pip/poetry/uv → pypi); others none (the build then fails closed). */
function packageSets(svcs: readonly Service[]): EgressSet[] {
  const out = new Set<EgressSet>();
  for (const s of svcs) {
    if (s.packageManager === 'npm') out.add('npm');
    else if (s.packageManager === 'pip' || s.packageManager === 'poetry' || s.packageManager === 'uv') out.add('pypi');
  }
  return [...out];
}

/** The registry set of a pinned image reference (`name:tag@sha256:…`). */
function imageSet(ref: string): EgressSet {
  const at = ref.indexOf('@');
  const name = (at === -1 ? ref : ref.slice(0, at)).replace(/:[^/:]*$/, '');
  const image = parseImageRef(name);
  if (image === null) throw new RenderError(`The image ${safeText(ref, 120)} is on a registry pipegen has no egress set for.`);
  return image.registry === 'ghcr.io' ? 'ghcr' : 'dockerhub';
}

/** A bash run step with no ambient startup file (BASH_ENV, ENV empty). */
const bash = (id: string, name: string, lines: readonly string[], env: Record<string, string> = {}): RenderedStep =>
  ({ id, name, run: lines.join('\n'), shell: 'bash', env: { BASH_ENV: '', ENV: '', ...env } });

/** The image tag app-start and sign-roundtrip build: `pipegen-proof/<compose key>:<commit>` (`$GITHUB_SHA` at run time). */
const imageTag = (key: string): string => `pipegen-proof/${key}:\${GITHUB_SHA}`;

/**
 * The compose override app-start writes (ruling B7): for each app service ONLY its `image:`, the one built with
 * `docker build --network host`; compose reads `${GITHUB_SHA}` from the step's environment. Computed here, checked by the
 * tests, written into runner temp by the job and never delivered (it is in no proof tree).
 */
export function proofOverrideText(apps: readonly Pick<ComposeApp, 'key'>[]): string {
  if (apps.length === 0) throw new RenderError('The compose override needs at least one app service.');
  const lines = ['services:'];
  for (const a of apps) {
    if (!/^app-[a-z0-9][a-z0-9-]{0,80}$/.test(a.key)) throw new RenderError(`${safeText(String(a.key), 60)} is not an app service key pipegen computes.`);
    lines.push(`  ${a.key}:`, `    image: "pipegen-proof/${a.key}:\${GITHUB_SHA:?}"`);
  }
  return `${lines.join('\n')}\n`;
}

/** The services whose image pipegen can build from `<folder>/Dockerfile` (existing, or created in this draft), with the compose key. */
function imageServices(draft: PipelineDraft, notes: string[]): { svc: Service; key: string; context: string }[] {
  const created = new Set(dockerfilesOf(draft.created));
  const out: { svc: Service; key: string; context: string }[] = [];
  for (const svc of draft.profile.services) {
    if (!isPlainFolder(svc.path)) { notes.push(`${safeText(svc.name, 60)}: its folder is not a plain path, so the harness builds no image for it.`); continue; }
    const dir = folderOf(svc.path);
    const dockerfile = dir === '' ? 'Dockerfile' : `${dir}/Dockerfile`;
    if (svc.dockerfile !== dockerfile && !created.has(dockerfile)) continue;
    let key: string;
    try { key = `app-${slug(svc.name)}`; } catch (e) {
      if (!(e instanceof ArtifactNameError)) throw e;
      notes.push(`${safeText(svc.name, 60)}: its name has no letters or digits, so the harness builds no image for it.`);
      continue;
    }
    out.push({ svc, key, context: dir === '' ? '.' : `./${dir}` });
  }
  return out;
}

function egressStep(sets: readonly EgressSet[], dockerNetworks: boolean): { step: RenderedStep; egress: EgressSet[] } {
  const egress = [...new Set(sets)].sort();
  return { step: renderEgressStep(egress, { dockerNetworks }), egress };
}

interface JobSpec { id: HarnessJobId; on: HarnessJob['on']; egress: EgressSet[]; dockerNetworks: boolean; steps: RenderedStep[]; permissions?: Record<string, string>; services?: Obj }

function egressCheckJob(): JobSpec {
  const e = egressStep([], false);
  return { id: 'egress-check', on: 'both', egress: e.egress, dockerNetworks: false, steps: [e.step, { ...renderEgressCheckStep(), id: 'egress-check', env: { BASH_ENV: '', ENV: '' } }] };
}

function appStartJob(draft: PipelineDraft, opts: HarnessOptions, list: readonly BaseImage[], notes: string[]): JobSpec | null {
  const file = draft.created.find((f) => f.repo === 'app' && f.path === COMPOSE_PATH);
  if (file === undefined) { notes.push('app-start: the draft has no docker-compose.pipegen.yml, so the app start is not proven here.'); return null; }
  const plan = planCompose(draft.profile, list, dockerfilesOf(draft.created));
  if (plan.text === null || plan.text !== file.content) { notes.push('app-start: the draft\'s docker-compose.pipegen.yml is not the file pipegen computes, so the harness does not start it.'); return null; }
  const services = plan.apps.map((a) => draft.profile.services.find((s) => s.name === a.service)).filter((s): s is Service => s !== undefined);
  const e = egressStep([...packageSets(services), 'dockerhub', ...list.map((b) => imageSet(`${b.image}:${b.tag}@${b.digest}`))], true);
  const steps: RenderedStep[] = [e.step, renderJobPrelude({}, opts.platform).steps[0] as RenderedStep, renderRuntimeEnv(plan.env)];
  for (const a of plan.apps) {
    if (!isPlainFolder(folderOf(a.context)) && a.context !== '.') throw new RenderError(`The build folder of ${a.key} is not plain.`);
    // ruling B7: build on the host network (S8: npm ETIMEDOUT inside docker build on the bridge network), from the service's own folder
    steps.push(bash(`repocode-${sha16(`proof-build:${a.key}`)}`, `pipegen: build ${a.key} (host network)`, [
      'set -euo pipefail', `docker build --network host -t "${imageTag(a.key)}" ${a.context}`,
    ]));
  }
  steps.push(bash(`proof-override-${sha16('override')}`, 'pipegen: write the proof compose override (image per app service, scratch only)', [
    'set -euo pipefail', 'mkdir -p "$RUNNER_TEMP/pipegen-proof"', `printf '%s' "$PIPEGEN_PROOF_OVERRIDE" > "${PROOF_OVERRIDE_PATH}"`,
  ], { PIPEGEN_PROOF_OVERRIDE: proofOverrideText(plan.apps) }));
  steps.push(renderComposeUp({ proofOverride: true }));
  for (const a of plan.apps) {
    if (!Number.isInteger(a.port) || a.port < 1 || a.port > 65535) throw new RenderError(`The port of ${a.key} is not a port.`);
    steps.push(bash(`proof-probe-${sha16(a.key)}`, `pipegen: probe ${a.key} on port ${a.port} (started = HTTP status below 500)`, [
      'set -uo pipefail',
      `code="$(curl --silent --retry 10 --retry-connrefused --retry-delay 3 --max-time 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:${a.port}/ || true)"`,
      `echo "${a.key} answered HTTP $code"`,
      'case "$code" in [1-4][0-9][0-9]) exit 0 ;; esac',
      `echo "::error::${a.key} did not start: HTTP $code (started means a status below 500)"`,
      `docker compose --env-file /dev/null -f docker-compose.pipegen.yml -f "${PROOF_OVERRIDE_PATH}" logs --no-color --tail 100 ${a.key} || true`,
      'exit 1',
    ]));
  }
  return { id: 'app-start', on: 'pull_request', egress: e.egress, dockerNetworks: true, steps };
}

function signRoundtripJob(draft: PipelineDraft, opts: HarnessOptions, reviewed: readonly ReviewedTool[], list: readonly BaseImage[], notes: string[]): JobSpec | null {
  if (opts.signing === 'none') { notes.push('sign-roundtrip: the delivered signing mode is none, so there is no signing to prove.'); return null; }
  const images = imageServices(draft, notes);
  if (images.length === 0) { notes.push('sign-roundtrip: no service has a Dockerfile, so there is no image to sign.'); return null; }
  const registry = tool(reviewed, 'registry');
  const cosign = tool(reviewed, 'cosign');
  const install = registry.step.cli?.install;
  const digest = registry.candidate.pin.digest;
  if (install === undefined || install.method !== 'docker' || digest === undefined || !/^sha256:[0-9a-f]{64}$/.test(digest)) throw new RenderError('The reviewed registry entry is not an image pinned by digest.');
  const image = `${install.package}:${install.version}@${digest}`;
  const cos = releaseInstallStep(cosign, 'pipegen-cosign');
  const e = egressStep([...packageSets(images.map((i) => i.svc)), 'dockerhub', ...list.map((b) => imageSet(`${b.image}:${b.tag}@${b.digest}`)), ...egressSetsForTool(cosign)], true);
  const keyDir = '$RUNNER_TEMP/pipegen-sign';
  const steps: RenderedStep[] = [e.step, renderJobPrelude({}, opts.platform).steps[0] as RenderedStep, cos.step,
    // a throwaway key pair made here: never stored, never a secret, gone with the runner (no Sigstore, no public log)
    bash(`proof-key-${sha16('key')}`, 'pipegen: make a throwaway signing key', [
      'set -euo pipefail', `mkdir -p "${keyDir}"`, `COSIGN_PASSWORD='' "${cos.bin}" generate-key-pair --output-key-prefix "${keyDir}/proof" > /dev/null`,
    ])];
  for (const i of images) {
    const ref = `localhost:${REGISTRY_PORT}/${imageTag(i.key)}`;
    steps.push(bash(`repocode-${sha16(`proof-sign:${i.key}`)}`, `pipegen: build, push, sign and verify ${i.key} (local registry, key-based, no transparency log)`, [
      'set -euo pipefail',
      `docker build --network host -t "${ref}" ${i.context}`,
      `docker push --quiet "${ref}" > /dev/null`,
      `ref="$(docker inspect --format '{{index .RepoDigests 0}}' "${ref}")"`,
      `case "$ref" in localhost:${REGISTRY_PORT}/*@sha256:*) ;; *) echo "::error::the pushed image has no digest from the local registry"; exit 1 ;; esac`,
      `COSIGN_PASSWORD='' "${cos.bin}" sign --yes --key "${keyDir}/proof.key" --tlog-upload=false --use-signing-config=false "$ref"`,
      `"${cos.bin}" verify --key "${keyDir}/proof.pub" --insecure-ignore-tlog=true "$ref" > /dev/null`,
      `echo "${i.key}: signed and verified"`,
    ]));
  }
  return {
    id: 'sign-roundtrip', on: 'pull_request', egress: e.egress, dockerNetworks: true, steps,
    services: { registry: { image, ports: [`127.0.0.1:${REGISTRY_PORT}:5000`] } },
  };
}

/** The service a created test file belongs to: the one whose folder holds it most closely. */
function serviceOfFile(path: string, services: readonly Service[]): Service | undefined {
  let best: Service | undefined;
  let depth = -1;
  for (const s of services) {
    if (!isPlainFolder(s.path)) continue;
    const dir = folderOf(s.path);
    if (dir !== '' && !path.startsWith(`${dir}/`)) continue;
    const d = dir === '' ? 0 : dir.split('/').length;
    if (d > depth) { best = s; depth = d; }
  }
  return best;
}

function testsRepeatJobs(draft: PipelineDraft, opts: HarnessOptions, reviewed: readonly ReviewedTool[], list: readonly BaseImage[], notes: string[]): JobSpec | null {
  if (opts.createdTests !== true) return null;
  const files = draft.created.filter((f) => f.repo === 'app' && f.part === 'tests');
  const svcs = [...new Set(files.map((f) => serviceOfFile(f.path, draft.profile.services)).filter((s): s is Service => s !== undefined))];
  if (svcs.length === 0) { notes.push('tests-repeat: no created test file belongs to a service, so there is nothing to run again.'); return null; }
  const vitest = tool(reviewed, 'vitest-coverage');
  const steps: RenderedStep[] = [];
  const sets: EgressSet[] = [];
  let node: RenderedStep[] | null = null;
  for (const svc of svcs.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (svc.language !== 'node' || svc.packageManager !== 'npm') { notes.push(`tests-repeat: ${safeText(svc.name, 60)} is not an npm service; its created tests are not run again here.`); continue; }
    let s: string;
    try { s = slug(svc.name); } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; notes.push(`tests-repeat: ${safeText(svc.name, 60)} has no letters or digits in its name.`); continue; }
    const prelude = renderJobPrelude({ node: { runtimeVersion: svc.runtimeVersion } }, opts.platform).steps;
    node ??= prelude;
    const major = prelude[1]?.with?.['node-version'];
    if (major === undefined || major !== node[1]?.with?.['node-version']) { notes.push(`tests-repeat: ${safeText(svc.name, 60)} needs another Node major than the first service; not run again here.`); continue; }
    const image = baseImageRef(nodeBaseImageId(svc.runtimeVersion, list).id, list);
    const artifact = `pipegen-out-junit-repeat-${s}`;
    steps.push(...renderStarterTestRun(svc, { vitest, image, nodeMajor: major, artifact }));
    steps.push({ ...renderPlatformStep('upload-artifact', opts.platform, { name: artifact, path: `\${{ runner.temp }}/pipegen-out/${artifact}` }), name: `Upload ${artifact}`, if: 'always()' });
    sets.push(...egressSetsForTool(vitest), imageSet(image));
  }
  if (node === null || steps.length === 0) return null;
  const e = egressStep(sets, false);
  return { id: 'tests-repeat', on: 'pull_request', egress: e.egress, dockerNetworks: false, steps: [e.step, ...node, ...steps] };
}

function verifyLookupJob(draft: PipelineDraft, opts: HarnessOptions, reviewed: readonly ReviewedTool[]): JobSpec {
  const pin = draft.centralPin;
  if ((pin === undefined) !== (opts.centralSha === undefined)) {
    throw new RenderError(pin === undefined ? 'The draft has no central pin (the inline layout), but a central sha was given.' : 'The draft has a central pin, but no proof central sha was given.');
  }
  if (opts.centralSha !== undefined && !SHA_RE.test(opts.centralSha)) throw new RenderError('The proof central sha is not a commit sha.');
  const gate = tool(reviewed, 'pipegen-gate');
  const central = pin === undefined || opts.centralSha === undefined ? undefined : { repo: pin.repo, sha: opts.centralSha, project: draft.profile.repo };
  const find = renderFindRunStep(gate, { ...(central === undefined ? {} : { central }), sha: 'github.sha', timeoutMinutes: FIND_RUN_MINUTES });
  const e = egressStep([], false);
  return { id: 'verify-lookup', on: 'push', egress: e.egress, dockerNetworks: false, steps: [e.step, find], permissions: { contents: 'read', actions: 'read' } };
}

/**
 * The proof harness workflow (see the file comment). Throws RenderError for a draft or options it can't render faithfully
 * (a central pin without the proof's central sha, a default branch git refuses, a reviewed entry missing).
 */
export function harnessWorkflow(draft: PipelineDraft, opts: HarnessOptions): Harness {
  const branch = draft.profile.defaultBranch;
  if (typeof branch !== 'string' || !validBranchName(branch)) throw new RenderError('The default branch is not a branch name pipegen can use.');
  if (typeof opts.createdTests !== 'boolean') throw new RenderError('createdTests is true or false.');
  const reviewed = opts.reviewed ?? loadReviewed();
  const list = opts.baseImages ?? loadBaseImages();
  const notes: string[] = [];
  const jobs: JobSpec[] = [egressCheckJob()];
  const app = appStartJob(draft, opts, list, notes);
  if (app !== null) jobs.push(app);
  const sign = signRoundtripJob(draft, opts, reviewed, list, notes);
  if (sign !== null) jobs.push(sign);
  const tests = testsRepeatJobs(draft, opts, reviewed, list, notes);
  if (tests !== null) jobs.push(tests);
  jobs.push(verifyLookupJob(draft, opts, reviewed));

  const doc = new Document(null, { version: '1.2' });
  const jobsNode = new YAMLMap();
  for (const j of jobs) {
    const m = new YAMLMap();
    m.set('name', `pipegen proof: ${j.id}`);
    if (j.on !== 'both') m.set('if', j.on === 'push' ? PUSH_ONLY : PR_ONLY);
    m.set('runs-on', RUNS_ON);
    m.set('timeout-minutes', JOB_MINUTES[j.id]);
    m.set('permissions', doc.createNode(j.permissions ?? { contents: 'read' }));
    if (j.services !== undefined) m.set('services', doc.createNode(j.services, { aliasDuplicateObjects: false }));
    m.set('steps', stepsToYaml(j.steps));
    jobsNode.set(j.id, m);
  }
  const root = new YAMLMap();
  root.set('name', 'pipegen proof harness (scratch only, never delivered)');
  root.set('on', doc.createNode({ pull_request: { branches: [branch] }, push: { branches: [branch] } }));
  root.set('permissions', new YAMLMap());
  root.set('jobs', jobsNode);
  doc.contents = root;
  doc.commentBefore = ' pipegen proof harness: runs only in the private scratch repo pipegen-proof-<repo>; never delivered (Plan E E3).';
  quoteStrings(doc);
  // G17-F1 round 3 (sec r2 M1): NEL, LS and PS as YAML escapes (every string is double-quoted here, so each one can be escaped)
  const content = escapeLineBreaks(doc.toString({ lineWidth: 0 }));
  if (content === null) throw new RenderError('The harness holds a line separator character pipegen can not write as an escape.');
  const back = parseYaml(content, 'strict');
  if ('problems' in back) throw new RenderError(`The harness does not parse back: ${back.problems[0] ?? ''}`);
  return {
    file: { path: HARNESS_PATH, content, part: 'pipeline', reason: 'The proof harness: the checks that only matter for proving (scratch repo only, never delivered).', repo: 'app' },
    jobs: jobs.map((j) => ({ id: j.id, on: j.on, egress: j.egress, dockerNetworks: j.dockerNetworks })),
    notes,
  };
}

// ---------- YAML output shared by the harness and the compat copies ----------

const PLAIN_KEY_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,200}$/;
/** Words a YAML 1.1 reader takes as a boolean or null: never written plain, also as a key. */
const YAML11_WORDS = /^(?:y|yes|n|no|true|false|on|off|null|~)$/i;
const BLOCK_SAFE = (v: string): boolean => v.includes('\n') && !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029\ufeff]|[ \t]\n|^\s/.test(v);

/**
 * Every string scalar double-quoted (a multi-line text without trailing spaces a block literal), keys plain only when they
 * are plain identifiers (the top-level `on` key stays plain, as GitHub writes it): no value can be read as another type by
 * any YAML reader.
 */
function quoteStrings(doc: Document): void {
  visit(doc, {
    Pair(_, pair, path) {
      const k = pair.key;
      if (isScalar(k) && typeof k.value === 'string') {
        const top = path.length === 2;   // Document → root map → this pair
        k.type = PLAIN_KEY_RE.test(k.value) && (!YAML11_WORDS.test(k.value) || (top && k.value === 'on')) ? Scalar.PLAIN : Scalar.QUOTE_DOUBLE;
      }
      if (isScalar(pair.value) && typeof pair.value.value === 'string') setValueType(pair.value as Scalar<string>);
    },
    Seq(_, seq) {
      for (const item of seq.items) if (isScalar(item) && typeof item.value === 'string') setValueType(item as Scalar<string>);
    },
  });
}
function setValueType(s: Scalar<string>): void {
  s.type = BLOCK_SAFE(s.value) ? Scalar.BLOCK_LITERAL : Scalar.QUOTE_DOUBLE;
}

// ---------- compat copies (S17, E2 r1-m3) ----------

export interface NotCompared { workflow: string; job: string; why: string }
export interface CompatResult { files: CreatedFile[]; notCompared: NotCompared[] }

/** Top-level workflow files GitHub runs (a sub-folder of .github/workflows is never run). */
const USER_WORKFLOW_RE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const RUN_TRIGGERS: ReadonlySet<string> = new Set(['push', 'pull_request', 'pull_request_target', 'merge_group']);
const WORKFLOW_KEYS: ReadonlySet<string> = new Set(['name', 'run-name', 'on', 'permissions', 'env', 'defaults', 'concurrency', 'jobs']);
/** Job keys a compat copy keeps (permissions and concurrency are replaced or dropped; the rest makes the job not compared). */
const JOB_KEYS: ReadonlySet<string> = new Set(['name', 'needs', 'if', 'runs-on', 'env', 'defaults', 'steps', 'timeout-minutes', 'strategy', 'continue-on-error', 'container', 'services', 'outputs', 'permissions', 'concurrency']);
const STEP_KEYS: ReadonlySet<string> = new Set(['id', 'if', 'name', 'uses', 'run', 'shell', 'with', 'env', 'continue-on-error', 'timeout-minutes', 'working-directory']);
/** A GitHub-hosted runner label (plan Task 2: ubuntu-*, windows-*, macos-*), written as plain text. */
const HOSTED_RE = /^(?:ubuntu|windows|macos)-[a-z0-9][a-z0-9.-]{0,40}$/;
const PERMISSION_LEVELS: ReadonlySet<string> = new Set(['read', 'none']);

function triggersOf(on: unknown): string[] {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.filter((t): t is string => typeof t === 'string');
  return isObj(on) ? Object.keys(on) : [];
}

/** Every string (keys and values) under a value, depth-first. */
function* strings(v: unknown): Generator<string> {
  if (typeof v === 'string') yield v;
  else if (Array.isArray(v)) for (const x of v) yield* strings(x);
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) { yield k; yield* strings(x); }
}

/**
 * Whether a text may read a secret other than GITHUB_TOKEN. Expressions are case-insensitive and may hold quoted `}}`, so
 * everything from the first `${{` on is searched (and the whole text of an `if`, which is always an expression); only
 * `secrets.GITHUB_TOKEN` is allowed. A plain run line that mentions "secrets" after an expression is a false positive
 * (the job is then not compared): the safe side.
 */
function readsSecret(text: string, wholeIsExpression: boolean): boolean {
  const at = text.indexOf('${{');
  const expr = wholeIsExpression ? text : at === -1 ? '' : text.slice(at);
  return /secrets/i.test(expr.replace(/\bsecrets\s*\.\s*github_token\b/gi, ''));
}

function usesSecrets(v: unknown): boolean {
  // fix round 4 (C1): also any text that names the secrets context outside an expression (the compat check refuses it)
  for (const s of strings(v)) if (readsSecret(s, false) || namesSecret(s)) return true;
  return false;
}
/** The `if` texts of a job and its steps (always expressions, with or without `${{`). */
function ifsOf(job: Obj): string[] {
  const out: string[] = [];
  if (typeof job.if === 'string') out.push(job.if);
  if (Array.isArray(job.steps)) for (const s of job.steps) if (isObj(s) && typeof s.if === 'string') out.push(s.if);
  return out;
}

/** Why a permissions value grants more than read (a write, id-token, write-all, an unknown form), or null. */
function permissionProblem(p: unknown): string | null {
  if (p === undefined || p === null) return null;
  if (p === 'read-all') return null;
  if (p === 'write-all') return 'it asks for write-all permissions';
  if (!isObj(p)) return 'its permissions are in a form pipegen does not read';
  for (const [k, v] of Object.entries(p)) {
    if (k === 'id-token' && v !== 'none') return 'it asks for an id-token';
    if (typeof v !== 'string' || !PERMISSION_LEVELS.has(v)) return `it asks for ${k}: ${typeof v === 'string' ? v : 'an unknown value'} (more than read)`;
  }
  return null;
}

/** A `uses` naming `<owner>/pipelines`: E2's central pin check would stop the whole proof on it. */
const namesPipelines = (u: unknown): boolean => typeof u === 'string' && (u.split('@')[0] ?? '').split('/')[1]?.toLowerCase() === 'pipelines';

/** Why one job can't be copied as a compat job (it would need more than a read-only, secret-free, GitHub-hosted run), or null. */
function jobProblem(id: string, job: unknown, wfPerms: unknown): string | null {
  if (!isObj(job)) return 'it is not a map of keys';
  if ('uses' in job) return 'it calls a reusable workflow';
  if ('secrets' in job) return 'it passes secrets (secrets: inherit or a list)';
  if ('environment' in job && job.environment !== null && job.environment !== undefined) return 'it uses an environment';
  for (const k of Object.keys(job)) if (!JOB_KEYS.has(k)) return `it has the key ${safeText(k, 40)}, which pipegen does not copy`;
  const perm = permissionProblem('permissions' in job ? job.permissions : wfPerms);
  if (perm !== null) return perm;
  if (usesSecrets(job) || ifsOf(job).some((t) => readsSecret(t, true))) return 'it uses a secret other than GITHUB_TOKEN';
  const ro = job['runs-on'];
  const label = Array.isArray(ro) && ro.length === 1 ? ro[0] : ro;
  if (typeof label !== 'string' || label.includes('${{') || !HOSTED_RE.test(label)) {
    return typeof label === 'string' && label.includes('${{') ? 'its runs-on is an expression or a matrix value' : 'it does not run on a plain GitHub-hosted runner (ubuntu-*, windows-*, macos-*)';
  }
  if (!Array.isArray(job.steps) || job.steps.length === 0) return 'it has no steps';
  for (const s of job.steps) {
    if (!isObj(s)) return 'a step is not a map of keys';
    for (const k of Object.keys(s)) if (!STEP_KEYS.has(k)) return `a step has the key ${safeText(k, 40)}, which pipegen does not copy`;
    if (namesPipelines(s.uses)) return 'a step uses a pipelines repository (the proof checks every such reference against the central draft)';
    // E3-R2: no proof job restores or saves a cache (a compat job could write the pull request's cache scope)
    if (typeof s.uses === 'string' && /^actions\/cache(?:\/|@|$)/i.test(s.uses)) return 'it uses actions/cache (no proof job restores or saves a cache)';
  }
  if (jobDeploys(job) || namesDeploy(id) || namesDeploy(job.name)) return 'it deploys, releases or publishes';
  return null;
}

/** The compat path for a user workflow, or null when the file name is not one pipegen writes. */
function compatPath(path: string): string | null {
  const file = path.slice('.github/workflows/'.length);
  const out = `${COMPAT_PREFIX}${file}`;
  return WORKFLOW_PATH_RE.test(out) ? out : null;
}

/**
 * The compat copy of one parsed workflow, re-rendered (never the user's text): the kept jobs with permissions contents: read,
 * concurrency dropped, the trigger pull_request only. Throws when the output would not parse back to exactly the model.
 */
function renderCompat(path: string, wf: Obj, jobs: [string, Obj][]): string {
  const model: Obj = { name: `pipegen compat: ${typeof wf.name === 'string' ? wf.name : path}`, on: 'pull_request', permissions: { contents: 'read' } };
  if ('env' in wf) model.env = wf.env;
  if ('defaults' in wf) model.defaults = wf.defaults;
  const out: Obj = {};
  for (const [id, job] of jobs) {
    const copy: Obj = {};
    for (const [k, v] of Object.entries(job)) if (k !== 'permissions' && k !== 'concurrency') copy[k] = structuredClone(v);
    copy.permissions = { contents: 'read' };
    out[id] = copy;
  }
  model.jobs = out;
  // aliasDuplicateObjects: false is what keeps anchors out: a value the user shared through an alias stays shared inside one
  // job even after structuredClone, and the default would write it as &a1/*a1. The strict parse-back below is the fail-safe:
  // an anchor that ever reached the text would make these jobs not compared, never pushed.
  const doc = new Document(model, { version: '1.2', aliasDuplicateObjects: false });
  doc.commentBefore = ` pipegen compat copy of ${path} (scratch only, never delivered): read-only, pull_request only, no secret referenced.`;
  quoteStrings(doc);
  // G17-F1 round 3 (sec r2 M1): NEL, LS and PS as YAML escapes, so the copy reads the same to every reader (and the proof's secret
  // names stay known); a character that can't be escaped makes these jobs not compared
  const text = escapeLineBreaks(doc.toString({ lineWidth: 0 }));
  if (text === null) throw new ProofStopError(`pipegen's compat copy of ${safeText(path, 120)} holds a line separator character it can not write as an escape.`);
  const back = parseYaml(text, 'strict');
  if ('problems' in back) throw new ProofStopError(`pipegen's compat copy of ${safeText(path, 120)} does not parse back (${back.problems[0] ?? ''}).`);
  if (!isDeepStrictEqual(back.parsed.js, model)) throw new ProofStopError(`pipegen's compat copy of ${safeText(path, 120)} does not read back as the model.`);
  return text;
}

/**
 * Compat copies of the user's workflows (`workflows`: HEAD's files under .github/workflows/, as text). See the file
 * comment. Never throws on a user file: what can't be modelled is listed as not compared.
 */
export function compatCopiesFrom(workflows: readonly { path: string; content: string }[]): CompatResult {
  const files: CreatedFile[] = [];
  const notCompared: NotCompared[] = [];
  const taken = new Set<string>();
  const sorted = [...workflows].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (const { path, content } of sorted) {
    const shown = safeText(path, 160);
    const whole = (why: string) => notCompared.push({ workflow: shown, job: '*', why });
    if (!USER_WORKFLOW_RE.test(path)) { whole('it is not a top-level workflow file (GitHub does not run it)'); continue; }
    const file = path.slice('.github/workflows/'.length);
    if (/^pipegen(?:[-.]|$)/i.test(file)) { whole('it is pipegen\'s own workflow; the draft\'s copy is proven instead'); continue; }
    const target = compatPath(path);
    if (target === null || safeText(path) !== path) { whole('its file name is not plain, so pipegen writes no copy of it'); continue; }
    if (taken.has(target.toLowerCase())) { whole('another workflow has the same name in another letter case'); continue; }
    const r = parseYaml(content, 'user');
    if ('problems' in r) { whole(`pipegen can't model it exactly (${r.problems[0] ?? 'not YAML'})`); continue; }
    const wf = r.parsed.js;
    const odd = Object.keys(wf).find((k) => !WORKFLOW_KEYS.has(k));
    if (odd !== undefined) { whole(`it has the key ${safeText(odd, 40)}, which pipegen does not copy`); continue; }
    if (!triggersOf(wf.on).some((t) => RUN_TRIGGERS.has(t))) { whole('it does not run on pushes or pull requests'); continue; }
    if (namesDeploy(file) || namesDeploy(wf.name)) { whole('it deploys, releases or publishes'); continue; }
    if (usesSecrets(wf.env) || usesSecrets(wf.defaults)) { whole('its workflow-level env or defaults use a secret other than GITHUB_TOKEN'); continue; }
    if (!isObj(wf.jobs) || Object.keys(wf.jobs).length === 0) { whole('it has no jobs pipegen can read'); continue; }
    const why = new Map<string, string>();
    for (const [id, job] of Object.entries(wf.jobs)) {
      const p = jobProblem(id, job, wf.permissions);
      if (p !== null) why.set(id, p);
    }
    // a job that needs a job that isn't compared is not compared either (to a fixed point)
    for (let changed = true; changed;) {
      changed = false;
      for (const [id, job] of Object.entries(wf.jobs)) {
        if (why.has(id) || !isObj(job)) continue;
        const needs = typeof job.needs === 'string' ? [job.needs] : Array.isArray(job.needs) ? job.needs : [];
        const dropped = needs.find((n) => typeof n !== 'string' || why.has(n));
        if (dropped !== undefined || (job.needs !== undefined && typeof job.needs !== 'string' && !Array.isArray(job.needs))) {
          why.set(id, `it needs ${typeof dropped === 'string' ? `the job ${safeText(dropped, 60)}, which is` : 'a job that is'} not compared`);
          changed = true;
        }
      }
    }
    for (const [id, w] of why) notCompared.push({ workflow: shown, job: safeText(id, 80), why: w });
    const kept = Object.entries(wf.jobs).filter(([id]) => !why.has(id)) as [string, Obj][];
    if (kept.length === 0) continue;
    let text: string;
    try { text = renderCompat(path, wf, kept); } catch (e) {
      if (!(e instanceof ProofStopError)) throw e;
      for (const [id] of kept) notCompared.push({ workflow: shown, job: safeText(id, 80), why: e.message });
      continue;
    }
    // fix round 4 (C1): never emit a copy the compat rules refuse (a stop of the whole proof): its jobs are not compared instead
    const own = proofWorkflowProblems({ path: target, content: text }, 'compat');
    if (own.length > 0) {
      for (const [id] of kept) notCompared.push({ workflow: shown, job: safeText(id, 80), why: `pipegen's copy would break the compat rules (${own[0] ?? ''})` });
      continue;
    }
    taken.add(target.toLowerCase());
    files.push(markCompatCopy({ path: target, content: text, part: 'pipeline' as const, reason: `A read-only copy of ${path} (build and test jobs only), to compare its result before and after pipegen's changes.`, repo: 'app' as const }));
  }
  return { files, notCompared };
}

/**
 * compatCopiesFrom over the workflows of `dir`'s HEAD (readSnapshot: the commit, never the working tree, as the base
 * snapshot). A workflow readSnapshot dropped (a symlink, an unsafe name) is listed as not compared.
 */
export async function compatCopies(p: RepoProfile, dir: string): Promise<CompatResult> {
  void p;
  const snap = await readSnapshot(dir);
  const workflows = snap.files.filter((f) => f.path.toLowerCase().startsWith('.github/workflows/') && /\.ya?ml$/i.test(f.path))
    .map((f) => ({ path: f.path, content: Buffer.from(f.content).toString('utf8') }));
  const r = compatCopiesFrom(workflows);
  for (const d of snap.dropped) {
    if (d.path.toLowerCase().startsWith('.github/workflows/')) r.notCompared.push({ workflow: safeText(d.path, 160), job: '*', why: `pipegen did not copy it (${d.why})` });
  }
  return r;
}

// ---------- the proof branch's files ----------

/** Plan G's assemble for this draft (injected): pipegen's files for the proof, at the given signing mode and central sha. */
export type ProofAssemble = (mode: typeof PROOF_SIGNING_MODE, centralSha: string | undefined) => CreatedFile[] | Promise<CreatedFile[]>;

export interface ProofAppFiles {
  /** pushProofSetup's `appFiles` (E2). */
  appFiles: (centralSha: string | undefined) => Promise<CreatedFile[]>;
  /** What the last call rendered: the harness, the compat copies (with what is not compared). */
  last(): { harness: Harness; compat: CompatResult } | null;
  /**
   * G14fix-R1 (review F2): the checks that need no central sha, before the setup (and so before any GitHub write): the assembled
   * workflows at no sha plus the compat copies of HEAD pass the proof rules, and no two of them (or the harness's path) share a path.
   * Only the harness waits for the sha; `appFiles` checks the full set again.
   */
  precheck?(): Promise<void>;
}

/**
 * The proof branch's files: assemble with signing mode `none` (always: no keyless signing and no public log from the scratch
 * repo; sign-roundtrip proves the delivered mode), the harness for the proof's central sha, and the compat copies of HEAD.
 * A path given twice is a stop.
 */
export function proofAppFiles(draft: PipelineDraft, deps: { assemble: ProofAssemble; harness: Omit<HarnessOptions, 'centralSha'>; dir: string }): ProofAppFiles {
  let last: { harness: Harness; compat: CompatResult } | null = null;
  return {
    appFiles: async (centralSha) => {
      const assembled = await deps.assemble(PROOF_SIGNING_MODE, centralSha);
      const harness = harnessWorkflow(draft, { ...deps.harness, ...(centralSha === undefined ? {} : { centralSha }) });
      const compat = await compatCopies(draft.profile, deps.dir);
      const all = [...assembled, harness.file, ...compat.files];
      const seen = new Set<string>();
      for (const f of all) {
        const k = f.path.toLowerCase();
        if (seen.has(k)) throw new ProofStopError(`Two proof files have the path ${safeText(f.path, 120)}; pipegen won't guess which one to push.`);
        seen.add(k);
      }
      // I1: every proof workflow, the assembled ones included, passes the proof rules (egress first, no dispatch-like trigger,
      // pinned actions, no cache); the compat copies under ruling E3-R2
      // m3: the compat kind comes only from the marker compatCopiesFrom sets (identity), never from a path; central callees
      // are checked for their shape here and resolved against the central tree when pushProofSetup checks again
      checkProofWorkflows(all.map((f) => ({ path: f.path, content: f.content, kind: isCompatCopy(f) ? 'compat' as const : 'proof' as const })), {
        ...(deps.harness.reviewed === undefined ? {} : { reviewed: deps.harness.reviewed }), central: 'later',
      });
      last = { harness, compat };
      return all;
    },
    last: () => last,
    precheck: async () => {
      const assembled = await deps.assemble(PROOF_SIGNING_MODE, undefined);
      const compat = await compatCopies(draft.profile, deps.dir);
      const all = [...assembled, ...compat.files];
      const seen = new Set<string>([HARNESS_PATH.toLowerCase()]);
      for (const f of all) {
        const k = f.path.toLowerCase();
        if (seen.has(k)) throw new ProofStopError(`Two proof files have the path ${safeText(f.path, 120)}; pipegen won't guess which one to push.`);
        seen.add(k);
      }
      checkProofWorkflows(all.map((f) => ({ path: f.path, content: f.content, kind: isCompatCopy(f) ? 'compat' as const : 'proof' as const })), {
        ...(deps.harness.reviewed === undefined ? {} : { reviewed: deps.harness.reviewed }), central: 'later',
      });
    },
  };
}
