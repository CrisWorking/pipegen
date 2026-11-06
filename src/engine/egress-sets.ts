// The reviewed egress host sets (v0.2 Plan E: E0d, ruling B5; E3-R1), a leaf with no imports so the bundled policy leaf tool-flags.ts
// can check a Bullfrog `allowed-domains` value against them (E9) and egress.ts can render it. Changing a set changes gate/dist.
/** The five labels of E0d (ruling B5). Since E9 the reviewed bullfrog entry offers these and the E3-R1 sets as its `allowed-domains` choices. */
export const REVIEWED_EGRESS_LABELS = Object.freeze(['github-core', 'npm', 'pypi', 'dockerhub', 'ghcr'] as const);
/** The exact-host sets added by ruling E3-R1 (labels of the reviewed bullfrog choices since E9). */
export const E3_EGRESS_SETS = Object.freeze(['github-releases', 'trivy-db', 'osv'] as const);
/**
 * G15a (carries A1-A3, the release blocker): the mode-scoped Sigstore set. It is in no tool's sets (egress.ts egressSetsForTool): only the
 * keyless verify job's egress step names it (egress.ts KEYLESS_VERIFY_SETS), and the referee refuses its hosts in any other job.
 */
export const SIGSTORE_SET = 'sigstore';
export const G15_EGRESS_SETS = Object.freeze([SIGSTORE_SET] as const);
/** A set name: one of the reviewed labels, an E3-R1 set or the G15 Sigstore set. */
export type EgressSet = typeof REVIEWED_EGRESS_LABELS[number] | typeof E3_EGRESS_SETS[number] | typeof G15_EGRESS_SETS[number];

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
 * G15a (carries A1-A3), sourced offline from the pinned cosign itself: the reviewed binary cosign v3.1.3 (cosign-linux-amd64, sha256
 * 4629c757..., the entry's pin), whose Go build info names its modules (sigstore-go v1.2.2, sigstore v1.10.8), disassembled with
 * `go tool objdump`; each host below is the string a call site loads, with that call site's upstream file and line. Mode-scoped: only the
 * keyless verify job gets it (egress.ts KEYLESS_VERIFY_SETS); it is in SHARED_CDN_SETS (anyone can write to the log), never in a tool's sets.
 * - sigstore:
 *   tuf-repo-cdn.sigstore.dev: Sigstore's TUF repository, where `cosign verify` reads its trusted root: cosign v3.1.3
 *   cmd/cosign/cli/verify/common.go:191 (SetTrustedMaterial calls cosign.TrustedRoot), pkg/cosign/tuf.go:84 (setTUFOpts, the default
 *   mirror), sigstore-go v1.2.2 pkg/tuf/options.go:142 (DefaultOptions, DefaultMirror); the live checklist verifies it under Bullfrog.
 *   rekor.sigstore.dev: the public transparency log: cosign v3.1.3 cmd/cosign/cli/verify/common.go:134 (SetLegacyClientsAndKeys, called
 *   by VerifyCommand.Exec, makes the Rekor client), the URL's default in cmd/cosign/cli/options/rekor.go:32-35 (RekorOptions.AddFlags).
 *   A signature that carries its log entry verifies offline, so whether verify really calls it is not known without a run: the live
 *   checklist verifies it (kept per the controller's start list, review-G4.md l. 77).
 *   Left out: fulcio.sigstore.dev (cmd/cosign/cli/options/fulcio.go:35, signcommon/common.go:435: signing only). The keyless sign job keeps
 *   its documented no-block exception (threat model T52): it also needs the per-run OIDC token host, which can not be listed exactly.
 * Not added: Sigstore hosts for the proof harness (it signs key-based with --tlog-upload=false, so none is needed); actions/attest
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
  [SIGSTORE_SET]: Object.freeze(['rekor.sigstore.dev', 'tuf-repo-cdn.sigstore.dev']),
});

