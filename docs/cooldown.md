# The 7-day cooldown

pipegen's own rule (DECISIONS #92): no new dependency version and no new pinned tool version may be less than 7 days old. A malicious or broken release is usually found and pulled within a few days, so waiting a week avoids most of that risk.

## What the check does

The `cooldown` job in `.github/workflows/ci.yml` runs on every pull request. It compares the PR with its base commit, looking at three files. The date always comes from upstream, never from a date written in the file, and the pin has to match the upstream release:

- `package-lock.json`: every entry that is new, or whose version, tarball or integrity changed, including packages pulled in by other packages. The name comes from the `node_modules/` path, the tarball must be the npm registry's own, the version must exist in the registry, and `integrity` must equal the registry's. The date is the registry publish time. Workspace links are skipped. An old lockfile format (below version 2), a lockfile without `packages`, or a removed lockfile fails.
- `data/reviewed-tools.yml`: any entry that changed (every field except `reviewedBy`, `reviewedAt` and `proofs`). An action's SHA must be the commit its tag points to; a release binary's checksum must be the digest GitHub records for that asset; a Docker digest must be the one Docker Hub shows for that tag; npm and pip tools and plugins are checked on their registries. The date is the release's `published_at`, or the registry or push time.
- `data/pinned-binaries.yml`: any tool that changed. Every platform's URL must be an asset of the GitHub release for that version, in the tool's own repo, with the recorded sha256.

If anything is under 7 days old, or cannot be tied to an upstream date, the job fails and lists each item. A tool kind or image the script cannot check (not on Docker Hub, no GitHub digest) fails with "needs owner review". Versions the PR did not change are never checked. A downgrade to an older version is fine.

## It fails closed

If the registry or GitHub cannot be reached, a date cannot be read, a lookup returns 404, or a date is in the future, the job fails. Re-run the failed job when the service is back. There is a cap of 150 distinct lookups and a 15 second timeout and a 32 MB size limit on each; a PR that changes more than that should be split. Parse errors never print file content.

## What it does not protect (known limitation)

The job checks out the base commit and runs the script from there, so a PR cannot change the script that judges it. That is all this protects. On a `pull_request` run the workflow file itself comes from the PR, so a PR can edit `ci.yml` (for example skip the job or point it at its own copy of the script). The check is therefore only as strong as enforced code-owner review of `/.github/` and `/scripts/` (see `.github/CODEOWNERS`).

GitHub Free private repositories have no rulesets, so that review is not enforced yet. This stays a known limitation until the release rulesets are applied before v0.4 (required checks, required code-owner review, no direct pushes to `main`). With such a ruleset, a solo owner cannot approve their own PRs, so the owner needs a ruleset bypass to merge them.

The bootstrap case is also open to a repeat: if `scripts/cooldown.ts` is ever deleted and merged, a later PR that adds it back runs without a base copy. The job fails when neither side has the script, but code-owner review is what stops a weakened script from being added back.

## Other limits

- GitHub Action SHA bumps in `.github/workflows/*.yml` are not checked here. Dependabot's own 7 day `cooldown` setting covers them.
- `.npmrc` has `min-release-age=7`, but the npm that ships with Node 24 ignores it (it only warns). This check is what enforces the rule on CI for the lockfile.
- There is no emergency path yet (the `security-fix` label from Plan R Task 4). Until it exists, an urgent fix has to wait or be merged by the owner outside this check.
