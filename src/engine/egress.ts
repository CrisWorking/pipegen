// The egress step every proof job starts with (v0.2 Plan E, sub-task E0d, ruling B5). Proof jobs run with the user's real
// test keys in their environment, so network egress is blocked except for the hosts the job needs (threats T21, T22, T32).
// pipegen uses Bullfrog for this (spike S8; Harden-Runner's free tier blocked nothing on a private repo, silently).
// - The reviewed `bullfrog` entry offers only labels as `allowed-domains` choices, one per input. Bullfrog would read a label
//   as a literal domain and block checkout, so this leaf expands the labels into reviewed host lists (EGRESS_DOMAIN_SETS).
// - The pin and the fixed inputs are read from the reviewed registry (loadReviewed), never written a second time here.
// - NOT YET ACCEPTED BY THE GATE: the bullfrog policy checker in tool-flags.ts (bundled into gate/dist) still accepts one
//   label per input. Until sub-task E9 changes it to accept the sorted union, a step rendered here would not pass today's
//   checker. That is deliberate: tool-flags.ts and the gate bundle do not change in E0d. Do not import this file from the gate entry.
// - Compat copies get no egress step (S17): the user's own hosts are unknown.
// - E3 (ruling E3-R1): proof jobs that scan or sign need hosts beyond the five reviewed sets. Each such host is a new
//   named set here, exact hosts only (no wildcard), with its source. The bullfrog choices in the reviewed YAML still list
//   the five labels (REVIEWED_EGRESS_LABELS); E9 adds the new labels there with the policy change. egressSetsForTool
//   says which sets a reviewed tool's step needs, so a job's egress step lists exactly those.
import type { ReviewedTool } from '../types.js';
import { parseImageRef } from './names.js';
import { RenderError, refuse, show } from './render-error.js';
import type { RenderedStep } from './job-rules.js';
import { loadReviewed } from './reviewed.js';

/** The five labels the reviewed bullfrog entry offers as `allowed-domains` choices today (a test compares them). */
export const REVIEWED_EGRESS_LABELS = Object.freeze(['github-core', 'npm', 'pypi', 'dockerhub', 'ghcr'] as const);
/** The exact-host sets added by ruling E3-R1 (E9 adds their labels to the reviewed bullfrog choices). */
export const E3_EGRESS_SETS = Object.freeze(['github-releases', 'trivy-db', 'osv'] as const);
/** A set name: one of the reviewed labels or an E3-R1 set. */
export type EgressSet = typeof REVIEWED_EGRESS_LABELS[number] | typeof E3_EGRESS_SETS[number];

/**
 * Reviewed by Claude (delegated by Cristiano, DECISIONS #105). Every host is an exact lowercase hostname: no wildcard, scheme,
 * port, path or trailing dot. Spike files are in ~/Code/pipegen-internal/spikes/.
 * Source per host (S8 = S8-egress.md; wf/ = spikes/scripts/S8/wf/; S5 = spikes/scripts/S5/wf-egress/jobs.yml):
 * - github-core: github.com, api.github.com, codeload.github.com: the Bullfrog allowlist sketch S8 l. 183-185. By workflow:
 *   github.com and api.github.com are in wf/egress.yml l. 56-57, 80-81, wf/egress2.yml l. 29-30, wf/egress3.yml l. 32-33 and
 *   S5 jobs.yml l. 12-13; codeload.github.com is in wf/egress.yml l. 58, 82, wf/egress2.yml l. 31 and S5 jobs.yml l. 14 (NOT in
 *   wf/egress3.yml, which only pulled images). The S5 run passed checkout, setup-node and `npm ci` (S8 l. 147).
 *   objects.githubusercontent.com: S5 jobs.yml l. 15 only (the same run).
 *   Left out on purpose (least privilege, controller ruling M1): pipelines.actions.githubusercontent.com and
 *   results-receiver.actions.githubusercontent.com. No spike run needed them (S4 and S8 name no artifact or results host), and
 *   artifacts can not work without the per-account blob host, which is excluded anyway. The live checklist decides.
 *   Also left out (ruling M3): raw.githubusercontent.com (S5 l. 16); setup-node/setup-python with a version not in the runner
 *   cache is a live-checklist item.
 * - npm: registry.npmjs.org: S8 l. 8, 75, 131 (reachable under Bullfrog block); in every spike list.
 * - pypi: pypi.org, files.pythonhosted.org: not measured in S8 (the registry's index and file hosts).
 * - dockerhub: registry-1.docker.io, auth.docker.io: wf/egress3.yml l. 35-36 and every S8 list; in the pull that passed (S8 l. 128-133).
 *   production.cloudfront.docker.com and the R2 host: S8 l. 127-128, 166, 204 (the first pull failed without them).
 *   production.cloudflare.docker.com: in every spike allowlist (wf/egress.yml l. 62 and 86, wf/egress2.yml l. 35, wf/egress3.yml l. 37,
 *   S5 jobs.yml l. 22), and the blob redirect target varies by run (S8 l. 127 went to cloudfront while it was listed), so it stays.
 * - ghcr: ghcr.io, pkg-containers.githubusercontent.com: wf/egress.yml l. 63-64, S5 jobs.yml l. 18-19; the ghcr gitleaks pull
 *   passed under that list (S8 l. 151).
 * Ruling E3-R1 (sub-task E3), each with NO spike evidence (no spike ran these tools under Bullfrog; the live checklist verifies):
 * - github-releases: release-assets.githubusercontent.com: where github.com/<repo>/releases/download/... redirects today
 *   (src/engine/pin.ts DOWNLOAD_HOSTS; the older target objects.githubusercontent.com is already in github-core). Needed by
 *   every github-release install (render-cli.ts releaseInstall: trivy, osv-scanner, nuclei, syft, zizmor, ...) and the
 *   harness's cosign. Left out: github-releases.githubusercontent.com (also in DOWNLOAD_HOSTS, an older name; live checklist).
 * - trivy-db: mirror.gcr.io: Trivy's default vulnerability DB repository (mirror.gcr.io/aquasec/trivy-db:2, falling back to
 *   ghcr.io/aquasecurity/trivy-db:2; tool catalogue l. 288, raw/runtime-security.md l. 57). Only trivy-image downloads
 *   the DB (trivy-config and trivy-licence run --skip-check-update and need no DB). The blob host behind mirror.gcr.io is
 *   not known without a live run: if it differs, the GHCR fallback (the ghcr set) carries the download.
 * - osv: api.osv.dev: osv-scanner sends package names and versions there (tool catalogue l. 176, 272;
 *   raw/code-security.md l. 74).
 * Not added: Sigstore hosts (the harness signs key-based with --tlog-upload=false, so none is needed); actions/attest
 * (its OIDC token URL is a per-run actions.githubusercontent.com host that can't be listed exactly: attestation stays
 * not-proven under Bullfrog); semgrep, nuclei and ZAP need none beyond github-core and their image registry (their rules
 * come from github.com archives; -duc/-ni/-silent/--metrics=off turn the other calls off).
 */
export const EGRESS_DOMAIN_SETS: Readonly<Record<EgressSet, readonly string[]>> = Object.freeze({
  'github-core': Object.freeze([
    'github.com', 'api.github.com', 'codeload.github.com', 'objects.githubusercontent.com',
  ]),
  npm: Object.freeze(['registry.npmjs.org']),
  pypi: Object.freeze(['pypi.org', 'files.pythonhosted.org']),
  dockerhub: Object.freeze([
    'registry-1.docker.io', 'auth.docker.io', 'production.cloudfront.docker.com', 'production.cloudflare.docker.com',
    'docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com',
  ]),
  ghcr: Object.freeze(['ghcr.io', 'pkg-containers.githubusercontent.com']),
  'github-releases': Object.freeze(['release-assets.githubusercontent.com']),
  'trivy-db': Object.freeze(['mirror.gcr.io']),
  osv: Object.freeze(['api.osv.dev']),
});

/**
 * Sets a tool needs at run time beyond its install (ruling E3-R1), by reviewed id. Reviewed data: a new entry that talks to
 * a host at run time must be added here, or its job fails at DNS under Bullfrog (fail closed).
 */
const RUNTIME_SETS: Readonly<Record<string, readonly EgressSet[]>> = Object.freeze({
  'trivy-image': Object.freeze(['trivy-db', 'ghcr'] as const),
  'osv-scanner': Object.freeze(['osv'] as const),
});

/**
 * What each reviewed ACTION reaches at run time (E3 review M1), beyond github-core. The runner fetches an action (and an image
 * its action.yml wraps) before the first step, so this is only what the action itself does once it runs. `verified`: the
 * hosts are known from a measured run or the action's own code path; false means the list is the best reading of its docs
 * and `liveCheck` says what the live session must confirm (an action missing here is refused, never mapped to nothing).
 */
export interface ActionEgress { sets: readonly EgressSet[]; verified: boolean; source: string; liveCheck?: string }
export const ACTION_EGRESS: Readonly<Record<string, ActionEgress>> = Object.freeze({
  'actions-checkout': { sets: [], verified: true, source: 'git fetch over https://github.com; S5 jobs.yml checkout passed under Bullfrog (S8 l. 147)' },
  bullfrog: { sets: [], verified: true, source: 'it downloads its agent from github.com releases before the block is on (S8 l. 16); measured in every S8 Bullfrog job' },
  'dependency-review-action': { sets: [], verified: true, source: 'it reads the dependency graph compare API on api.github.com (the action\'s documented API; no other host)' },
  'codeql-upload-sarif': { sets: [], verified: true, source: 'it posts the SARIF to the code scanning API on api.github.com; not rendered in the scratch repo (ruling S18)' },
  'docker-login-action': { sets: ['ghcr'], verified: true, source: 'the reviewed choice registry is ghcr.io only (reviewed-tools.yml docker-login-action); it logs in to ghcr.io' },
  'actions-setup-node': { sets: [], verified: false, source: 'the runner tool cache when the version is there (S5 setup-node 24 passed); else a download from the actions/node-versions manifest (raw.githubusercontent.com, left out by ruling E0d-4) and nodejs.org', liveCheck: 'setup-node with a Node version not in the runner cache (E0d-4)' },
  'actions-setup-python': { sets: [], verified: false, source: 'the runner tool cache when the version is there; else the actions/python-versions manifest and release download (E0d-4)', liveCheck: 'setup-python with a version not in the runner cache (E0d-4)' },
  'actions-upload-artifact': { sets: [], verified: false, source: 'the results service and the per-account blob store host (E0d-2: the blob host can not be listed exactly); S8 l. 151: the secrets and image-build jobs, each with an upload step, passed under Bullfrog without it (suggestive only)', liveCheck: 'artifact upload under Bullfrog (E0d-2)' },
  'actions-download-artifact': { sets: [], verified: false, source: 'as upload-artifact: the results service and the blob store (E0d-2)', liveCheck: 'artifact download under Bullfrog (E0d-2)' },
  'docker-setup-buildx-action': { sets: ['dockerhub'], verified: false, source: 'the default docker-container driver pulls moby/buildkit from Docker Hub (buildx driver docs; review-E3 M1)', liveCheck: 'setup-buildx under Bullfrog pulls moby/buildkit with the dockerhub set' },
  'docker-build-push-action': { sets: [], verified: false, source: 'it reaches what the Dockerfile and the push target need (base images, package registries, ghcr); the job adds those sets for its own build', liveCheck: 'build-push of a created Dockerfile under Bullfrog' },
  'scorecard-action': { sets: ['osv'], verified: false, source: 'the Vulnerabilities check queries api.osv.dev even with publish_results false (review-E3 M1, Scorecard docs); its other checks use api.github.com', liveCheck: 'scorecard under Bullfrog: any host beyond api.osv.dev and github-core' },
  'actions-attest': { sets: [], verified: false, source: 'it needs the OIDC token URL (a per-run actions.githubusercontent.com host that can not be listed exactly) and Sigstore or GitHub\'s signing hosts: attestation stays not-proven under Bullfrog', liveCheck: 'attestation can not run under an exact-host list; keep not-proven' },
  'pypi-publish': { sets: [], verified: false, source: 'it uploads to upload.pypi.org with an OIDC token; publishing never runs in the proof', liveCheck: 'none: never proven in the scratch repo' },
  'pipegen-gate': { sets: [], verified: false, source: 'api.github.com (github-core) for runs and artifacts, plus the artifact zip redirect to the blob store (gate STORE_HOST_RE; E0d-2)', liveCheck: 'the gate\'s artifact downloads under Bullfrog (E0d-2)' },
});

/**
 * The egress sets a reviewed tool's step needs, sorted (github-core is always added by renderEgressStep): for an action its
 * ACTION_EGRESS entry (an action not there is refused); else its install (github-release → github-releases, npm → npm,
 * pip → pypi, docker → the image's registry) and RUNTIME_SETS. Throws RenderError for an install method, image registry or
 * action it can not map (never a guess).
 */
export function egressSetsForTool(tool: ReviewedTool): EgressSet[] {
  if (tool.step.action !== undefined) {
    const a = Object.hasOwn(ACTION_EGRESS, tool.id) ? ACTION_EGRESS[tool.id] : undefined;
    if (a === undefined) return refuse(`The action ${show(tool.id)} has no reviewed egress entry; add one with its source.`);
    return [...a.sets].sort();
  }
  const out = new Set<EgressSet>(Object.hasOwn(RUNTIME_SETS, tool.id) ? RUNTIME_SETS[tool.id] : []);
  const cli = tool.step.cli;
  const installs = cli === undefined ? [] : [cli.install, ...(cli.plugins ?? [])];
  for (const i of installs) {
    const method: unknown = i.method;
    if (method === 'github-release') out.add('github-releases');
    else if (method === 'npm') out.add('npm');
    else if (method === 'pip') out.add('pypi');
    else if (method === 'docker') {
      const image = parseImageRef(i.package);
      if (image === null) return refuse(`The image of ${show(tool.id)} is on a registry pipegen has no egress set for.`);
      out.add(image.registry === 'ghcr.io' ? 'ghcr' : 'dockerhub');
    } else return refuse(`The install method ${show(method)} of ${show(tool.id)} has no egress set.`);
  }
  return [...out].sort();
}

/** The Docker network range a job's services and containers use (the reviewed `allowed-ips` choice). */
const DOCKER_RANGE = '172.16.0.0/12';

/**
 * The egress step: the reviewed bullfrog pin and fixed inputs, `allowed-domains` as the sorted, de-duplicated union of the
 * named sets (one host per line), and `allowed-ips` only when `dockerNetworks`. `github-core` is always included (ruling
 * E0d-1: every job checks out). An empty list is valid. Throws RenderError for an unknown set, a raw domain or a non-boolean.
 */
export function renderEgressStep(sets: readonly EgressSet[], opts: { dockerNetworks: boolean }): RenderedStep {
  if (!Array.isArray(sets)) return refuse('The egress sets must be a list.');
  if (opts === null || typeof opts !== 'object' || typeof opts.dockerNetworks !== 'boolean') return refuse('dockerNetworks must be true or false.');
  const hosts = new Set<string>(EGRESS_DOMAIN_SETS['github-core']);
  for (const name of sets) {
    const list = typeof name === 'string' && Object.hasOwn(EGRESS_DOMAIN_SETS, name) ? EGRESS_DOMAIN_SETS[name as EgressSet] : undefined;
    if (list === undefined) return refuse(`${show(name)} is not a reviewed egress set (${Object.keys(EGRESS_DOMAIN_SETS).join(', ')}). A raw domain is never accepted.`);
    for (const h of list) hosts.add(h);
  }
  const tool = loadReviewed().find((t) => t.id === 'bullfrog');
  const uses = tool?.step.action?.uses;
  if (tool === undefined || uses === undefined) throw new RenderError('The reviewed list has no bullfrog entry.');
  const withs: Record<string, string> = { ...(tool.fixedInputs.with ?? {}), 'allowed-domains': [...hosts].sort().join('\n') };
  if (opts.dockerNetworks) withs['allowed-ips'] = DOCKER_RANGE;
  return { name: 'Limit network egress', uses, usesComment: tool.candidate.version, with: withs };
}

/**
 * A fixed step for E3 to place right after the egress step: a request to a host that is not allowed, and one to a raw IP, must
 * FAIL the way a block fails. curl exit 6 (no DNS), 7 (refused) or 28 (timeout) counts as blocked (6 only for the name: no DNS
 * is involved for an IP). Exit 0 fails the job (egress is open). Any other exit (TLS 35, empty reply 52, recv 56, HTTP/2 92,
 * proxy 5, CA 60 ...) means a connection was made or the test was not direct, so it fails too, with the code named.
 * `-q` (no curlrc) and `--noproxy '*'` plus unset proxy variables keep the probe direct. `|| rc=$?` is safe under `set -e`.
 * A missing curl fails the step: it could not prove anything.
 */
export function renderEgressCheckStep(): RenderedStep {
  const run = [
    '# a BASH_ENV or env-defined shell function named curl must not stand in for the real one',
    'unset -f curl',
    'unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY',
    'if ! command -v curl >/dev/null 2>&1; then',
    '  echo "::error::egress check could not run: curl is missing, so the block was not verified"',
    '  exit 1',
    'fi',
    'probe() {',
    '  url="$1"; shift',
    '  rc=0',
    `  command curl -q --noproxy '*' --silent --max-time 10 --output /dev/null "$url" || rc=$?`,
    '  if [ "$rc" -eq 0 ]; then',
    '    echo "::error::egress is open: $url answered, so the allowlist is not blocking"',
    '    exit 1',
    '  fi',
    '  for ok in "$@"; do',
    '    if [ "$rc" -eq "$ok" ]; then',
    '      echo "$url blocked as expected (curl exit $rc)"',
    '      return 0',
    '    fi',
    '  done',
    '  echo "::error::egress check inconclusive for $url: curl exit $rc is not a block (connection, TLS or proxy problem)"',
    '  exit 1',
    '}',
    'probe https://example.com 6 7 28',
    'probe https://1.1.1.1 7 28',
  ].join('\n');
  return { name: 'Check egress is blocked', shell: 'bash', run };
}
