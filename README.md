# pipegen *(working name)*

**Add secret scanning, code scanning, tests and signed builds to your GitHub repo with one command.**
For small teams with nobody dedicated to security, DevOps or code quality.
It opens one pull request. You review it. It never touches your app code or your `main` branch.

> **Status: early, not published yet.** `pipegen audit` (read-only) is built and tested on real public repos; it is not on npm yet, so the commands below would run someone else's package: don't run them until the first release. The full run (one PR) comes later. See the [roadmap](docs/roadmap.md).

## What the audit shows you *(excerpt of a real run on a public repo, expressjs/express; "..." marks cut parts)*

```text
$ npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo

pipegen audit: expressjs/express

Verdict: 4 of 4 layers have gaps; 4 are serious. pipegen couldn't check everything in 1 layer.
Scheduled and repo-file checks: gaps (1 of 2 checks covered).

...

  On a schedule and in repo files: gaps (1 of 2 checks covered)
      partial  Dependency update config (warning only)
               Dependabot's default wait is 3 days; pipegen uses 7. Set cooldown default-days to at
               least 7 (with no lower per-type days, include or exclude) on every entry.
               Found: dependabot in .github/dependabot.yml
      covered  OpenSSF Scorecard (warning only)
               The scorecard check runs on a schedule or on every push to the default branch.
               Found: scorecard in .github/workflows/scorecard.yml (job analysis)

...

Checks that don't apply here
  - Type check (for express): no tsconfig.json or typescript dependency found
  - Dockerfile lint (for express): no Dockerfile found
  ...

After the setup PR is merged, pipegen would turn on:
  - Require actions pinned to a commit: Makes GitHub refuse any action that is not pinned to a
    commit. pipegen turns it on only after your other workflows pin their actions to a commit. Today
    none of your 5 workflows use tag pins; pipegen can't see this setting with read access, so it
    can't say whether it is already on.
  ...
```

[See the full example report →](examples/audit-example.md)

## What the audit checks

Every check below is a row in the report: covered, partial, missing or unknown. A check that blocks a merge when it is missing is marked serious; the ones that only warn say **warning only**.

- **Before each commit:** a git hook manager, a secret scan, a format and lint hook.
- **On every push and pull request:** secret scan, code scan (SAST), dependency check, unit and full tests, lint, format, type check, test coverage minimum, dead code and unused dependencies, copy-paste check, Dockerfile lint, workflow lint, action pin check, new-dependency review, licence check, running-app scan (DAST), API scan against the spec, infrastructure code scan, container image build and scan, and the merge gate.
- **At deploy or release:** SBOM, image signing, build attestation, trusted publishing, a network lock for release jobs and the deploy check.
- **On a schedule and in repo files:** dependency update config (Dependabot or Renovate with a 7-day wait), OpenSSF Scorecard and fuzzing.

Checks that do not apply to a repo (no Dockerfile, no tests, no API spec) are listed with the reason, in "Checks that don't apply here". The report also lists the GitHub settings the setup would turn on after the pull request is merged, and what it can't see.

The code scan can use Semgrep CE with rules that pipegen pins to one reviewed commit of `semgrep/semgrep-rules`. Those rules are under the Semgrep Rules License v1.0, which is not an open-source licence: using them to scan your own code is allowed; reselling them or offering them as a service is not.

## What the full run does (v0.2)

pipegen reads your project, works out what a complete pipeline needs, **creates what's missing** (like a Dockerfile or tests), **proves everything works on real GitHub runners** before you see anything, and opens **one PR** with a plain-English `PIPEGEN.md` explaining every choice.

It protects four stages: **pre-commit → push → merge → deploy**.

## What it touches, and what it never touches

| ✅ It does | ❌ It never does |
|---|---|
| Adds workflow files, configs, a Dockerfile/compose/tests when they're missing | Edit your application's source code |
| Opens **one PR** (you review and merge) | Push to your `main` branch |
| For private projects: uses two **private** helper repos (`pipelines`, `pipegen-proof-<repo>`) | Make any repo public, or suggest it |
| Stores the keys you give it as **GitHub secrets** | Write a secret into a file, log, PR or chat |
| Applies merge rules **after** you merge the PR | Deploy your app |

## Permissions and cost (honest numbers before you start)

- **Access:** in v0.2 you use a **fine-grained token** limited to the repos involved (set as `GITHUB_TOKEN`). Broad classic tokens are refused by default. pipegen prints the `gh repo create <owner>/pipelines --private` and `gh repo create <owner>/pipegen-proof-<repo> --private` commands for you to run, empties the scratch repo after the proof instead of deleting it, and `pipegen uninstall --delete-repos` prints the `gh repo delete` commands. pipegen's own GitHub App login (which makes and deletes these repos itself) is planned next.
  `pipegen audit` only reads: on a private repo, give the token just Metadata: read, Pull requests: read, Actions: read
  and Code scanning alerts: read (optional; without it pipegen can't confirm code scanning). A public repo works without a token.
  The full run (`pipegen run`, then `finish`, `verify` and `update`) needs, on the app repo and the private helper repos: Metadata: read,
  Contents, Workflows, Pull requests, Actions, Secrets, Variables, Environments and Administration (read and write), and Issues: read
  (`pipegen update` reads the update issues). For a repo owned by an organisation, two organisation permissions are optional:
  Administration (read and write, for the organisation rule that makes pipegen's required workflow run) and Members: read (to check that
  you own the organisation and to suggest code owners). Without them pipegen plans no organisation rule and says so.
- **Shown before anything runs:** setup Actions minutes (hard limit 2× the estimate), **monthly** minutes afterwards, approximate AI cost (or "free" with a local model), and approximate time.
- **GitHub Free + private repos:** merge locks need GitHub Pro (personal) or Team (organisation), and required deploy reviewers on private repos need GitHub Enterprise. pipegen checks what your repo really allows, sets up everything else and tells you exactly what's missing. Image signing works on Free private repos too, when pipegen can confirm the signing environment's branch rule (only your default branch may use the key).

## Commands *(planned)*

> **Not on npm yet: don't run these until the first release.** The npm name isn't published yet, so until then `npx pipegen` would run whatever package holds the name (see [Install safely](#install-safely-and-check-what-you-installed)).

Inside your project folder:

```bash
npx pipegen               # read-only report of this folder; it shows the type it found for each service
                          # (static site, library, CLI, server, container) and asks "Is this right? (Y/n)"
                          # before it reads GitHub
npx pipegen --out ../report.md
                          # also save the report as a Markdown file, outside the repo
                          # (--json prints the report as JSON instead of text; --verbose prints the full report)
npx pipegen --type web=static-site
                          # set a service's type yourself (--type static-site when the repo has one service);
                          # no question is asked then
npx pipegen --ai          # also ask an AI for extra checks and tools to mention, after it shows what it would send
                          # and asks you (default No)
```

Without a terminal (CI, a pipe) or with `--json`, pipegen asks nothing: the report shows the types it found.

**Safe mode, for a repo you don't trust** (someone else's repo, or a branch you haven't read): run pipegen from the
folder above the repo, with an exact version and npm's own registry, so nothing in the repo can change which pipegen runs:

```bash
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo
```

Why: inside a folder, npm reads that folder's `.npmrc` and prefers a local `node_modules/.bin/pipegen`, so a repo
can make `npx pipegen` run something else. When pipegen starts in a folder (or under one, up to that repo's top) whose
`.npmrc` has settings that can change what npm runs, or that has a local pipegen or a committed `node_modules`, it stops
before reading the repo and prints the safe-mode command (exit code `4`). It can't stop a fake pipegen that runs instead of it, or code a hostile
`.npmrc` makes npm load before pipegen starts: only safe mode avoids those.

Exit codes of `pipegen audit`:

- `0`: the report was printed (and written, with `--out`); also when you cancel the type question (Ctrl+C or Esc):
  then nothing is read from GitHub and no report is printed.
- `1`: a refusal or an error, including GitHub not readable at all (a private repo without access, a refused token, no
  answer): only what is on disk is printed, and no `--out` file is written.
- `3`: the report was printed (and written, with `--out`), but GitHub's rate limit stopped pipegen reading some GitHub
  facts. Every check that needs them shows as unknown ("couldn't check"), never as covered or missing; the warning at
  the top says when the limit resets. In `--json`, `githubIncomplete` lists what wasn't read (`unread`), the reset time
  (`resetsAt`) and how many rows it left unknown (`rows`); it is `null` on a complete run. Without a token GitHub allows
  60 requests an hour; a read-only fine-grained token with the permissions above allows 5,000. One case still exits `1`
  without a report: the limit hit while pipegen checks a GitHub App login set in `GITHUB_TOKEN` (pipegen can't confirm
  which repos that login reaches without GitHub).
- `4`: pipegen stopped before reading the repo, because a folder npm read when pipegen started could change which
  pipegen runs (see safe mode above).

`audit --ai` needs Linux or macOS for now (WSL works): it checks your code for secrets with a pinned betterleaks binary
before anything is sent (or gitleaks, the fallback, when `PIPEGEN_SECRET_SCANNER` is set to `gitleaks`), and those
binaries exist for those systems only.

Later versions add the full job (one PR), then `finish` (after you merge: merge rules, signing key and dates), `verify`
(read-only: checks nobody weakened the pipeline files) and `uninstall`. Their exact commands will be shown here when
they exist. No pipegen command, these included, is safe to run before the first release, because the npm name isn't
published yet.

## Uninstall (v0.2)

> Like every command here: not safe to run before the first release (the npm name isn't published yet).

```bash
npx pipegen uninstall                  # first run, then (after you merge its pull request) the second run
npx pipegen uninstall --delete-repos   # the second run also prints the gh repo delete commands for the repos pipegen made (v0.2: it deletes none)
```

`pipegen uninstall` needs a terminal. It shows what it will do, asks **one** yes, and asks you to type a name before it deletes anything it can't be sure is pipegen's. With no terminal (CI, a pipe) it stops before it reads or sends anything. No flag or environment variable answers these questions.

**Two runs, and why.** The first run opens a pull request (`pipegen/uninstall`) that takes pipegen out of your app, closes pipegen's own open pull requests and removes the merge locks (the branch rules and the organisation rule; classic branch protection is put back as it was). You merge that pull request. The second run starts only when GitHub says it is merged: it removes the secrets, variables, environments and settings pipegen added, empties the proof's scratch repo, and opens a pull request in your central `pipelines` repo that removes this project's files (the install record last). Two runs because the uninstall pull request deletes `pipegen.yml`, so the required `pipegen / gate` check can never report on it; deploys may still need the secrets until it is merged; and the install record is the only list of what pipegen made, so it goes last. Run `pipegen uninstall` again after each merge. If a run is cut short, run it again: it goes on from what it saved.

**What it removes.** Only what the install record lists as created by pipegen **and** what GitHub shows with the same id and creation time as recorded. Anything else is kept and listed ("not the one pipegen created"). Files you took over (`adopted`) are kept unless you say yes; secrets named `PIPEGEN_...` that pipegen created are removed directly, a secret with your own name only after you type it; a secret pipegen overwrote is never deleted. Environments that existed before get their previous settings back.

**Exit codes.** `0`: the run did what it set out to (first run done, waiting for you to merge, the uninstall is finished). `1`: you said no. `2`: it stopped, a step failed, or it finished with something left for you (a kept item, a manual step; the final message lists each). `4`: pipegen stopped before reading the repo because of the folder it was started in (see safe mode above).

**`--delete-repos`.** In v0.2 (a fine-grained token) pipegen deletes no repo: it prints the `gh repo delete` commands, for the scratch repo and for the central repo only when yours is the last project, the central pull request is merged and the repo holds nothing but pipegen's files. pipegen prints a delete command only after those checks, and never after a refusal. pipegen's own GitHub App login (which makes and deletes these repos itself) is planned next. With it, `--delete-repos` will use the repo-deletion right the App has (Administration: write) and delete them after you type their names. A pull request branch `pipegen/update-<name>` left on the central repo withholds the command (pipegen records no head for it, so it can't tell it from a teammate's work): delete that branch yourself, then run again.

**Permissions.** The same write permissions as `pipegen run` on the app repo and the helper repos. For an organisation: Administration (read and write) is optional, for removing the organisation rule that made pipegen's required workflow run (without it pipegen tells you to remove the rule by hand), and Members: read is optional too (it checks that you own the organisation). `--delete-repos` needs no extra permission in v0.2 (it only prints commands; you run `gh repo delete` with your own login).

**Known limits.**
- A `<name>--required.yml` that pipegen keeps because the organisation rule still requires it leaves the second run unfinished until you remove the organisation rule; remove the rule, then the file, then run again.
- pipegen doesn't pass a corporate proxy through (neither `HTTPS_PROXY` nor `NO_PROXY`, for git or for the GitHub API), so the proof, and the commands that talk to GitHub, don't work behind a mandatory proxy in v0.2.
- v0.2 installs no pipegen GitHub App (it uses your fine-grained token), so there is no App to remove. When you are done, delete the token on GitHub (Settings → Developer settings → Fine-grained personal access tokens) or take the repos out of its access. The final message of the second run says this too. Once the App login exists (planned next), the same message will tell you how to remove the App by hand.

## Install safely, and check what you installed

pipegen is not published yet: until the first release, `npx pipegen` would run whatever package holds the name on npm,
so don't run it before then. Once it is published, `npx pipegen` in your own project folder is the normal way to run it.
An unversioned run takes whatever the registry serves at that moment; for a repo you don't trust, use safe mode, with
the exact version and the registry:

```bash
npx --registry=https://registry.npmjs.org pipegen@x.y.z audit --dir ./my-repo
```

Replace `x.y.z` with the version from the release page; do not copy a version from anywhere else. Run it from outside the repo you audit.

To check a release, in an empty folder:

```bash
npm init -y
npm install --registry=https://registry.npmjs.org pipegen@x.y.z
npm audit signatures --registry=https://registry.npmjs.org
```

`npm audit signatures` verifies the registry signature and the provenance attestation of every installed package: it
should report the package as having a verified attestation. Then open the version's page on npmjs.com, follow the
provenance link to the GitHub Actions run, and check that it is a run of `release.yml` in this repository for the matching tag.
You can also verify the downloaded release file with `gh attestation verify <file>.tgz --repo CrisWorking/pipegen`.
The steps for making a release are in [docs/release.md](docs/release.md).

## Maintenance promise

- **Updates:** the latest minor version is maintained. Fixes ship as new patch versions; nothing is changed in an existing
  version after release.
- **Security fixes:** report a problem privately (see [SECURITY.md](SECURITY.md)), not in a public issue. A report gets an
  acknowledgement within 7 days and a fix or a written plan within 30 days.
- **Dependencies and tools:** pipegen ships with no runtime dependencies, and every pinned dependency or tool version waits
  7 days after its release before it is used (see [the cooldown](docs/cooldown.md)). An urgent security fix may skip the wait only with the maintainer's approval each time, and the exception is printed in the check (see [the emergency path](docs/cooldown.md#the-emergency-path-for-urgent-security-fixes)).
- **Releases:** every release is built in GitHub Actions from an annotated tag signed by the maintainer's key listed in `.github/release-signers` (the workflow fails otherwise), with a provenance attestation you can verify as above.
- **Side project:** pipegen is open source and maintained by one person; replies may be slow, and the promise above is the
  part that is not.

## Read more

- [Design](docs/design.md)
- [Threat model](docs/threat-model.md): who could attack, and what stops them
- [Roadmap](docs/roadmap.md)

## Licence

[Apache-2.0](LICENSE).
