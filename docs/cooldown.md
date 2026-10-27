# The 7-day cooldown

pipegen's own rule (DECISIONS #92): no new dependency version and no new pinned tool version may be less than 7 days old. A malicious or broken release is usually found and pulled within a few days, so waiting a week avoids most of that risk.

## What the check does

The `cooldown` job in `.github/workflows/ci.yml` runs on every pull request. It compares the PR with its base branch, looking at three files:

- `package-lock.json`: every package version that is new, including packages pulled in by other packages. The publish time comes from the npm registry.
- `data/reviewed-tools.yml` and `data/pinned-binaries.yml`: every tool that was added or whose pin changed. The date is the one recorded in the file (`releasedAt`, or `pinnedOn` if there is none). For tools hosted on GitHub, the check also reads the release's `published_at` from GitHub, and the younger date counts. A file that claims an old date does not fool it.

If anything is under 7 days old, the job fails and lists each item with its age. Versions the PR did not change are never checked. A removed package, or a downgrade to an older version, is fine.

## It fails closed

If the registry or GitHub cannot be reached, a date cannot be read, or a date is in the future, the job fails. Re-run the failed job when the service is back. Lookups are limited (a cap of 150 and a 15 second timeout each); a PR that changes more than that should be split.

## Why the base copy runs

The job checks out the base commit and runs the script from there, against the PR's files, which are only read. If it ran the PR's own copy, a PR could weaken the check that judges it. The first PR that adds the script has no base copy, so that one run does nothing (it prints a notice).

## Limits

- GitHub Action SHA bumps in `.github/workflows/*.yml` are not checked here. Dependabot's own 7 day `cooldown` setting covers them.
- `.npmrc` has `min-release-age=7`, but the npm that ships with Node 24 ignores it (it only warns). This check is what enforces the rule on CI.
- There is no emergency path yet (the `security-fix` label from Plan R Task 4). Until it exists, an urgent fix has to wait or be merged by the owner outside this check.
