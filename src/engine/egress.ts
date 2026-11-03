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
import { RenderError, refuse, show } from './render-error.js';
import type { RenderedStep } from './job-rules.js';
import { loadReviewed } from './reviewed.js';

/** The set names: they equal the reviewed bullfrog `allowed-domains` choices (a test compares them). */
export type EgressSet = 'github-core' | 'npm' | 'pypi' | 'dockerhub' | 'ghcr';

/**
 * Reviewed by Claude (delegated by Cristiano, DECISIONS #105). Every host is an exact lowercase hostname: no wildcard, scheme,
 * port, path or trailing dot. Spike files are in ~/Code/pipegen-internal/spikes/.
 * Source per host (S8 = S8-egress.md; wf/ = spikes/scripts/S8/wf/; S5 = spikes/scripts/S5/wf-egress/jobs.yml):
 * - github-core: github.com, api.github.com, codeload.github.com: in the Bullfrog allowlist sketch S8 l. 183-185 and in every spike
 *   workflow list; the runs that passed checkout and `npm ci` (S8 l. 147). objects.githubusercontent.com: S5 jobs.yml l. 15, in the
 *   run that passed checkout, setup-node and `npm ci` (S8 l. 147).
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
});

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
    if (list === undefined) return refuse(`${show(name)} is not a reviewed egress set (github-core, npm, pypi, dockerhub, ghcr). A raw domain is never accepted.`);
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
    'unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY',
    'if ! command -v curl >/dev/null 2>&1; then',
    '  echo "::error::egress check could not run: curl is missing, so the block was not verified"',
    '  exit 1',
    'fi',
    'probe() {',
    '  url="$1"; shift',
    '  rc=0',
    `  curl -q --noproxy '*' --silent --max-time 10 --output /dev/null "$url" || rc=$?`,
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
