# The 7-day cooldown

pipegen's own rule (DECISIONS #92): no new dependency version and no new pinned tool version may be less than 7 days old. A malicious or broken release is usually found and pulled within a few days, so waiting a week avoids most of that risk.

## What the check does

The `cooldown` job in `.github/workflows/ci.yml` runs on every pull request. It compares the PR with its base commit, looking at three files. The date always comes from upstream, never from a date written in the file, and the pin has to match the upstream release:

- `package-lock.json`: every entry that is new, or whose version, tarball or integrity changed, including packages pulled in by other packages. The name comes from the `node_modules/` path, the tarball must be the npm registry's own, the version must exist in the registry, and `integrity` must equal the registry's. The date is the registry publish time. A package whose full registry document is over the 32 MB size limit (vite is about 39 MB) is read from its version document (`/<name>/<version>`) instead. It is dated by the later of two times: the `Last-Modified` time of its registry tarball, and the publish stamp the registry writes into the version document (when there is one). The registry stores the tarball when the version is published and a version can never be published again, so neither time is earlier than the publish. Workspace links are skipped. An old lockfile format (below version 2), a lockfile without `packages`, or a removed lockfile fails.
- `data/reviewed-tools.yml`: any entry that changed (every field except `reviewedBy`, `reviewedAt` and `proofs`). An action's SHA must be the commit its tag points to; a release binary's checksum must be the digest GitHub records for that asset; a Docker digest must be the one Docker Hub shows for that tag. An npm or pip tool's package (`step.cli.install.package`, not the candidate id) must have the hash in `candidate.pin.checksum` on its registry (npm: the `dist.integrity`; PyPI: the sha256 of one of that release's files), and every `step.cli.plugins` entry its own `checksum`, each with its own date; a plugin installed any other way fails. The date is the release's `published_at`, or the registry or push time.
  - Archives a tool downloads when it runs are pins too (`step.cli.env`, which must agree with `fixedInputs.env`). The **nuclei templates** tarball (`PIPEGEN_NUCLEI_TEMPLATES_URL`/`_SHA256`) is a GitHub tag archive with no recorded digest. Its sha256 must be the one the release's own `nuclei-templates-<version>_checksums.txt` lists; that file is downloaded and must match the digest GitHub records for it. A release-asset URL must have that asset's digest instead. The date is the youngest of the release's `published_at` and the file's `created_at`/`updated_at`. The **semgrep rules** archive (`PIPEGEN_RULES_URL`/`_TREE`) must be exactly `https://github.com/semgrep/semgrep-rules/archive/<commit>.tar.gz` (the loader refuses any other repo too). That commit's tree must be `PIPEGEN_RULES_TREE`, and the date is the `verification.verified_at` GitHub set when it verified the commit's signature. The git author and committer dates are whatever the pusher wrote, so they are never used: an unsigned rules commit fails with "needs owner review".
  - **The commit must be upstream's.** GitHub serves a commit pushed only to a fork under the upstream repo's API and archive URLs too, because forks share objects. So the rules commit, and the commit the nuclei templates tag points to, must be on the repo's default branch. The branch is read from the repo, never assumed. `compare/<commit>...<branch>` must be `ahead` or `identical`. A side branch or a fork's commit fails with "needs owner review". A compare that returns 404 (GitHub could not compare at all) is reported as a failed lookup, and fails too. Actions are tied through the upstream repo's own tag ref, which a fork can't set.
  - `PIPEGEN_RULES_SHA256` is the hash of GitHub's archive of that commit, and it is not looked up here. The commit and tree are tied, so the hash can't stand for other rules; a wrong hash only makes the download fail. **Renderer requirement (v0.2, not written yet):** download only `PIPEGEN_RULES_URL`, check `PIPEGEN_RULES_SHA256` before extracting, and check that the archive's commit id (`git get-tar-commit-id`) is the commit in the URL.
  - A value that looks like a hash (40 or 64 hex characters, `sha256:`, `sha512-`) or a URL, at any field the script does not know, fails with "needs owner review". So a new kind of pin can't be skipped silently. The known fields are the pins above, `verifiedWith` (pin-time signature checks, never installed) and `wrappedImage.digest`.
  - An entry without an `id`, an `id` used twice, or a `tools` that is not a list fails: one copy of an entry must never hide another.
- `data/pinned-binaries.yml`: any tool that changed. Every platform's URL must be an asset of the GitHub release for that version, in the tool's own repo, with the recorded sha256. A top-level value that is not a tool, a duplicate tool name (a YAML error), or a hash- or URL-shaped value at a field other than a platform's `url`, `archiveSha256` or `binarySha256` fails.
- `data/base-images.yml`: any entry that changed (every field except `reviewedBy` and `reviewedAt`). The image must be a bare official Docker Hub name, the digest must be the one Docker Hub shows for that tag, and the date is the tag's last push. A file whose `images` is not a list, or an entry with a missing or duplicate id, fails.

If anything is under 7 days old, or cannot be tied to an upstream date, the job fails and lists each item (unless the emergency path below applies). A tool kind or image the script cannot check (not on Docker Hub, no GitHub digest) fails with "needs owner review". Versions the PR did not change are never checked. A downgrade to an older version is fine, with one exception: a package too big for the full registry document is dated by its tarball's `Last-Modified`. The registry sometimes stores old tarballs again (vite 5.0.0, published in 2023, shows 2026), so a downgrade of such a package can look young. That is the safe direction. Wait until the date is 7 days old, or use the emergency path below.

## Pins nobody changed

The check above only looks at what a PR adds or changes. Upstream can still drift under an old pin: a tag moved to
other code, a release asset uploaded again with other bytes, a Docker tag pointing at another digest. The
`pins-upstream` job in `.github/workflows/ci.yml` runs `test/pins-upstream-live.test.ts`, which ties **every** pin of
`data/reviewed-tools.yml` and `data/pinned-binaries.yml` to upstream again with this same script's code (as if all were
new). It fails on any pin that no longer ties. Age is left to the check above. It runs on pull requests that change
`data/`, on every push to `main` and once a week (a schedule, so drift is seen even when nobody pushes). On
other pull requests the job passes without running.

## It fails closed

If the registry or GitHub cannot be reached, a date cannot be read, a lookup returns 404, or a date is in the future, the job fails. Re-run the failed job when the service is back. There is a cap of 150 distinct lookups and a 15 second timeout and a 32 MB size limit on each; a PR that changes more than that should be split. The size limit is never raised: an npm document over it takes the smaller lookups above. Parse errors never print file content.

GitHub's API allows few requests without a token. The CI jobs pass `GITHUB_TOKEN`; for a run by hand, pass one too, for example `GITHUB_TOKEN=$(gh auth token) node scripts/release-check.ts --tag vX.Y.Z`. A GitHub 403 or 429 still fails the check, and its message says whether a token was set.

## The emergency path for urgent security fixes

A security fix that cannot wait 7 days can pass the age rule, but only with the maintainer's approval each time (DECISIONS #103):

1. A **code owner applies the `security-fix` label** to the PR. Code owners are the users on the `/data/` and `/scripts/` lines of `.github/CODEOWNERS` in the **base** commit (never the PR's copy); both lines must list the same users, as `@login` entries. The script asks the GitHub API who applied the label (the latest `labeled` event for it) and fails when that was anyone else, a bot included.
2. The **PR body has a line `Security-fix-reason: <why>`**. The first such line counts and must not be empty. The job prints the reason (one line, at most 300 characters, with control characters, mentions and links made inert).
3. **The owner's approval is tied to the exact commit by a review**, because GitHub records which commit a review was given on (a label is not tied to any commit):
   - **With one owner (today):** the owner adds a review on the PR's current head commit, either "Comment" (works on their own PR) or "Approve", whose text has a line that is exactly `Security-fix-approved`. The owner's latest such review counts; a later dismissal or change request from them cancels it.
   - **With two or more owners:** owners other than the PR author approve the current head commit: two of them, or one when the author is one of only two owners. Each user's latest review counts, so a later comment, change request or dismissal cancels an approval.

   A review on an older commit never counts. **After every new push, the owner adds a new `Security-fix-approved` review (or the owners approve again) on the new head.**

The job re-runs when the label is added or removed, when the PR body is edited and on every push. Reviews do not re-run it: after the review, re-run the `cooldown` job.

The path does not apply to `data/base-images.yml`: the loader (`src/engine/base-images.ts`) has its own 7 day rule (`releasedAt` at least 7 days before `pinnedOn`), which the label does not lift. A security fix to a base image waits 7 days or needs a code change.

What it does not change: the path only lifts the age rule. Every other check (registry identity, integrity, SHA and digest match, an upstream date that exists and is not in the future, the lookup cap) still applies, and the path is not considered at all while any other problem remains. Any error reading the PR, its events or its reviews fails the job. When the job passes this way, it says so and lists each young item that passed only because of the label, so the exception stays visible.

Its limits: with one owner, nobody but the owner looks at the PR, so read the listed items before writing the review. And like the rest of this check it is only as strong as enforced code-owner review (next section): a PR can still edit the workflow, and only code-owner review, not enforced yet, stops that.

## What it does not protect (known limitation)

The job checks out the base commit and runs the script from there, so a PR cannot change the script that judges it. That is all this protects. On a `pull_request` run the workflow file itself comes from the PR, so a PR can edit `ci.yml` (for example skip the job or point it at its own copy of the script). The check is therefore only as strong as enforced code-owner review of `/.github/` and `/scripts/` (see `.github/CODEOWNERS`).

GitHub Free private repositories have no rulesets, so that review is not enforced yet. This stays a known limitation until the release rulesets are applied before v0.4 (required checks, required code-owner review, no direct pushes to `main`). With such a ruleset, a solo owner cannot approve their own PRs, so the owner needs a ruleset bypass to merge them.

The bootstrap case is also open to a repeat: if `scripts/cooldown.ts` is ever deleted and merged, a later PR that adds it back runs without a base copy. The job fails when neither side has the script, but code-owner review is what stops a weakened script from being added back.

## Other limits

- An action's `wrappedImage` in `data/reviewed-tools.yml` (scorecard-action's GHCR image) is a record of the image the action's own `action.yml` runs, not a pin pipegen installs; the action itself is checked by its commit SHA.
- The dependencies of npm and pip tools (eslint's dependency tree, bandit's PyYAML and others) are not pinned in `data/reviewed-tools.yml`, so they are not checked here. Only the tool's own package and its listed plugins are.
- GitHub Action SHA bumps in `.github/workflows/*.yml` are not checked here. Dependabot's own 7 day `cooldown` setting covers them.
- `.npmrc` has `min-release-age=7`, but the npm that ships with Node 24 ignores it (it only warns). This check is what enforces the rule on CI for the lockfile.
