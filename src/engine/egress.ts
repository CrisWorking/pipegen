// The egress step every proof job starts with (v0.2 Plan E, sub-task E0d, ruling B5). Proof jobs run with the user's real
// test keys in their environment, so network egress is blocked except for the hosts the job needs (threats T21, T22, T32).
// pipegen uses Bullfrog for this (spike S8; Harden-Runner's free tier blocked nothing on a private repo, silently).
// - The reviewed `bullfrog` entry offers only labels as `allowed-domains` choices, one per input. Bullfrog would read a label
//   as a literal domain and block checkout, so this leaf expands the labels into reviewed host lists (EGRESS_DOMAIN_SETS).
// - The pin and the fixed inputs are read from the reviewed registry (loadReviewed), never written a second time here.
// - Since E9 the bullfrog policy (tool-flags.ts allowedDomainsProblem, bundled into gate/dist) accepts exactly this form: the sorted,
//   de-duplicated union of whole reviewed sets, github-core among them. The sets live in the leaf egress-sets.ts for that reason.
//   Do not import this file from the gate entry.
// - Compat copies get no egress step (S17): the user's own hosts are unknown.
// - E3 (ruling E3-R1): proof jobs that scan or sign need hosts beyond the five reviewed sets. Each such host is a new
//   named set (egress-sets.ts), exact hosts only (no wildcard), with its source. Since E9 the bullfrog choices in the reviewed YAML
//   list all eight labels. egressSetsForTool
//   says which sets a reviewed tool's step needs, so a job's egress step lists exactly those.
import type { ReviewedTool } from '../types.js';
import { parseImageRef } from './names.js';
import { RenderError, refuse, show } from './render-error.js';
import type { RenderedStep } from './job-rules.js';
import { loadReviewed } from './reviewed.js';
import { egressDomains } from './tool-flags.js';

export { E3_EGRESS_SETS, EGRESS_DOMAIN_SETS, G15_EGRESS_SETS, GITHUB_ATTEST_SET, REVIEWED_EGRESS_LABELS, SIGSTORE_SET, type EgressSet } from './egress-sets.js';
import { EGRESS_DOMAIN_SETS, GITHUB_ATTEST_SET, SIGSTORE_SET, type EgressSet } from './egress-sets.js';

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

/**
 * E3-R3 (E-b5): the egress sets whose hosts serve anyone's content (release assets, the OSV API, the Trivy DB mirror): never in a job with a
 * user secret. G15a: the Sigstore set too (anyone can write an entry to the public transparency log, so it could carry a secret out).
 */
export const SHARED_CDN_SETS: ReadonlySet<EgressSet> = new Set<EgressSet>(['github-releases', 'osv', 'trivy-db', SIGSTORE_SET, GITHUB_ATTEST_SET]);

/**
 * G15a (carries A2, A3; open question 1, mode-scoped): the sets the keyless verify job adds to cosign's own (cosign verify reads Sigstore's
 * trusted root and log). Not in cosign's RUNTIME_SETS: those feed the proof harness and the key-env sign job, which need no Sigstore host.
 */
export const KEYLESS_VERIFY_SETS: readonly EgressSet[] = Object.freeze([SIGSTORE_SET]);

/**
 * G15a (ruling G15a-R0b item 2): the sets the attest verify job reaches beyond its install and ghcr: gh's own hosts (the github-attest set,
 * each host cited in egress-sets.ts from the pinned gh v2.103.3 source and one live reading). gh runs with --no-public-good there, so the
 * public-good TUF is never fetched. null would refuse attest verify (fail closed) while a host is uncited.
 */
export const ATTEST_VERIFY_SETS: readonly EgressSet[] | null = Object.freeze([GITHUB_ATTEST_SET]);
/** Said only while ATTEST_VERIFY_SETS is null (a reviewed host of gh is missing): attest verify is then refused, never written to fail. */
export const ATTEST_VERIFY_REFUSAL = 'gh reads the trust root of GitHub\'s own signing service from a host that is in no reviewed network set yet, so behind the network lock the verify job could only fail; pipegen refuses the attest deploy check instead of writing a job that never passes';

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
  for (const name of sets) {
    if (typeof name !== 'string' || !Object.hasOwn(EGRESS_DOMAIN_SETS, name)) return refuse(`${show(name)} is not a reviewed egress set (${Object.keys(EGRESS_DOMAIN_SETS).join(', ')}). A raw domain is never accepted.`);
  }
  const tool = loadReviewed().find((t) => t.id === 'bullfrog');
  const uses = tool?.step.action?.uses;
  if (tool === undefined || uses === undefined) throw new RenderError('The reviewed list has no bullfrog entry.');
  // E9: the one rule (tool-flags.ts, bundled): github-core plus the sets, sorted, each host once
  const withs: Record<string, string> = { ...(tool.fixedInputs.with ?? {}), 'allowed-domains': egressDomains(sets as string[]) };
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
