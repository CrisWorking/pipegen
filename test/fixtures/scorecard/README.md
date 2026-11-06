# Scorecard SARIF fixtures (real runs)

Captured live on 2026-11-06 by the controller (progress line "Scorecard SARIF fixtures (real)"):

- the scorecard CLI v5.6.0, the library version scorecard-action v2.5.0 (the reviewed entry) runs; tarball sha256
  19bde071…dd9a, equal to the release's scorecard_checksums.txt;
- `ENABLE_SARIF=1`, `--format sarif`, `--policy policy.yml` (scorecard's `policies/template.yml` at v5.6.0, copied here unchanged);
- `scorecard-action.sarif`: run against ossf/scorecard-action; `hello-world.sarif`: run against octocat/Hello-World.

No token is in either file. The gate's Scorecard reader (gate/src/sarif.ts, `SARIF_TOOLS['scorecard-action']`) is tested on them in
test/g15-scorecard.test.ts.
