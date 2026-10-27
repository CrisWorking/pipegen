# The 7-day cooldown

pipegen's own rule (DECISIONS #92): no new dependency version and no new pinned tool version may be less than 7 days old. A malicious or broken release is usually found and pulled within a few days, so waiting a week avoids most of that risk.

## What the check does

The `cooldown` job in `.github/workflows/ci.yml` runs on every pull request. It compares the PR with its base commit, looking at three files. The date always comes from upstream, never from a date written in the file, and the pin has to match the upstream release:

- `package-lock.json`: every entry that is new, or whose version, tarball or integrity changed, including packages pulled in by other packages. The name comes from the `node_modules/` path, the tarball must be the npm registry's own, the version must exist in the registry, and `integrity` must equal the registry's. The date is the registry publish time. Workspace links are skipped. An old lockfile format (below version 2), a lockfile without `packages`, or a removed lockfile fails.
- `data/reviewed-tools.yml`: any entry that changed (every field except `reviewedBy`, `reviewedAt` and `proofs`). An action's SHA must be the commit its tag points to; a release binary's checksum must be the digest GitHub records for that asset; a Docker digest must be the one Docker Hub shows for that tag; npm and pip tools and plugins are checked on their registries. The date is the release's `published_at`, or the registry or push time.
- `data/pinned-binaries.yml`: any tool that changed. Every platform's URL must be an asset of the GitHub release for that version, in the tool's own repo, with the recorded sha256.

If anything is under 7 days old, or cannot be tied to an upstream date, the job fails and lists each item (unless the emergency path below applies). A tool kind or image the script cannot check (not on Docker Hub, no GitHub digest) fails with "needs owner review". Versions the PR did not change are never checked. A downgrade to an older version is fine.

## It fails closed

If the registry or GitHub cannot be reached, a date cannot be read, a lookup returns 404, or a date is in the future, the job fails. Re-run the failed job when the service is back. There is a cap of 150 distinct lookups and a 15 second timeout and a 32 MB size limit on each; a PR that changes more than that should be split. Parse errors never print file content.

## The emergency path for urgent security fixes

A security fix that cannot wait 7 days can pass the age rule, but only with the maintainer's approval each time (DECISIONS #103):

1. A **code owner applies the `security-fix` label** to the PR. Code owners are the users on the `/data/` and `/scripts/` lines of `.github/CODEOWNERS` in the **base** commit (never the PR's copy); both lines must list the same users, as `@login` entries. The script asks the GitHub API who applied the label (the latest `labeled` event for it) and fails when that was anyone else, a bot included.
2. The **PR body has a line `Security-fix-reason: <why>`**. The first such line counts and must not be empty. The job prints the reason (one line, at most 300 characters, with control characters, mentions and links made inert).
3. **When CODEOWNERS lists two or more owners**, two of them other than the PR author must also approve the PR's current head commit. Each user's latest review counts, so a later comment, change request or dismissal cancels an approval, and an approval of an older commit does not count. With one owner (today), steps 1 and 2 are enough.

The job re-runs when the label is added or removed and when the PR body is edited. Reviews do not re-run it: after the approvals, re-run the `cooldown` job.

What it does not change: the path only lifts the age rule. Every other check (registry identity, integrity, SHA and digest match, an upstream date that exists and is not in the future, the lookup cap) still applies, and the path is not considered at all while any other problem remains. Any error reading the PR, its events or its reviews fails the job. When the job passes this way, it says so and lists each young item that passed only because of the label, so the exception stays visible.

Its limits: with one owner, the label is not tied to a commit, so a push after the label was applied still passes if it only adds young items; read the listed items before merging. And like the rest of this check it is only as strong as enforced code-owner review (next section): a PR can still edit the workflow, and only code-owner review, not enforced yet, stops that.

## What it does not protect (known limitation)

The job checks out the base commit and runs the script from there, so a PR cannot change the script that judges it. That is all this protects. On a `pull_request` run the workflow file itself comes from the PR, so a PR can edit `ci.yml` (for example skip the job or point it at its own copy of the script). The check is therefore only as strong as enforced code-owner review of `/.github/` and `/scripts/` (see `.github/CODEOWNERS`).

GitHub Free private repositories have no rulesets, so that review is not enforced yet. This stays a known limitation until the release rulesets are applied before v0.4 (required checks, required code-owner review, no direct pushes to `main`). With such a ruleset, a solo owner cannot approve their own PRs, so the owner needs a ruleset bypass to merge them.

The bootstrap case is also open to a repeat: if `scripts/cooldown.ts` is ever deleted and merged, a later PR that adds it back runs without a base copy. The job fails when neither side has the script, but code-owner review is what stops a weakened script from being added back.

## Other limits

- GitHub Action SHA bumps in `.github/workflows/*.yml` are not checked here. Dependabot's own 7 day `cooldown` setting covers them.
- `.npmrc` has `min-release-age=7`, but the npm that ships with Node 24 ignores it (it only warns). This check is what enforces the rule on CI for the lockfile.
