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
 * Source per host:
 * - github-core: github.com, api.github.com, codeload.github.com: S8-egress.md l. 183-185 (the allowlist sketch; github.com also l. 146).
 *   objects.githubusercontent.com: release/archive downloads redirect there (the brief's list; not measured in S8).
 *   results-receiver.actions.githubusercontent.com, pipelines.actions.githubusercontent.com: the Actions artifact/results
 *   service. S4-artifacts.md and S8-egress.md name NO artifact or results host (grep of both found none), so these two come
 *   from GitHub's documented runner endpoints, NOT from a spike. Live checklist must confirm them. Artifact v4 blobs also go
 *   to a per-account `*.blob.core.windows.net` host that can not be listed exactly (no wildcards); see the report.
 * - npm: registry.npmjs.org: S8-egress.md l. 8 (the allowed probe host), l. 75 and l. 131 (reachable under Bullfrog block).
 * - pypi: pypi.org, files.pythonhosted.org: the registry's index and file hosts (not measured in S8).
 * - dockerhub: production.cloudfront.docker.com and the R2 blob host: S8-egress.md l. 127-128 (first pull failed without
 *   them), l. 166, l. 204. registry-1.docker.io, auth.docker.io: the registry and its token service (the pull in S8 l. 127 used them; not named).
 * - ghcr: ghcr.io, pkg-containers.githubusercontent.com: the registry and its blob host (not measured in S8).
 */
export const EGRESS_DOMAIN_SETS: Readonly<Record<EgressSet, readonly string[]>> = Object.freeze({
  'github-core': Object.freeze([
    'github.com', 'api.github.com', 'codeload.github.com', 'objects.githubusercontent.com',
    'results-receiver.actions.githubusercontent.com', 'pipelines.actions.githubusercontent.com',
  ]),
  npm: Object.freeze(['registry.npmjs.org']),
  pypi: Object.freeze(['pypi.org', 'files.pythonhosted.org']),
  dockerhub: Object.freeze([
    'registry-1.docker.io', 'auth.docker.io', 'production.cloudfront.docker.com',
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
 * A fixed step for E3 to place right after the egress step: curl to a host that is not allowed must FAIL. The job fails if
 * the request succeeds. `if curl …` is exempt from `set -e`, so an exit code can not turn into a silent pass; a missing curl
 * fails the step (it could not prove anything).
 */
export function renderEgressCheckStep(): RenderedStep {
  const run = [
    'if ! command -v curl >/dev/null 2>&1; then',
    '  echo "::error::egress check could not run: curl is missing, so the block was not verified"',
    '  exit 1',
    'fi',
    'if curl --silent --max-time 10 --output /dev/null https://example.com; then',
    '  echo "::error::egress is open: https://example.com answered, so the allowlist is not blocking"',
    '  exit 1',
    'fi',
    'echo "egress blocked as expected"',
  ].join('\n');
  return { name: 'Check egress is blocked', shell: 'bash', run };
}
