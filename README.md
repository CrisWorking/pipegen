# pipegen *(working name)*

**Add secret scanning, code scanning, tests and signed builds to your GitHub repo with one command.**
For small teams with nobody dedicated to security, DevOps or code quality.
It opens one pull request. You review it. It never touches your app code or your `main` branch.

> **Status: early, not published yet.** `pipegen audit` (read-only) is built and tested on real public repos; it is not on npm yet, so the commands below don't work until the first release. The full run (one PR) comes later. See the [roadmap](docs/roadmap.md).

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

- **Access:** a GitHub App or fine-grained token limited to the repos involved. Broad classic tokens are refused by default.
  `pipegen audit` only reads: on a private repo, give the token just Metadata: read, Pull requests: read, Actions: read
  and Code scanning alerts: read (optional; without it pipegen can't confirm code scanning). A public repo works without a token.
- **Shown before anything runs:** setup Actions minutes (hard limit 2× the estimate), **monthly** minutes afterwards, approximate AI cost (or "free" with a local model), and approximate time.
- **GitHub Free + private repos:** merge locks need GitHub Pro (personal) or Team (organisation), and required deploy reviewers on private repos need GitHub Enterprise. pipegen checks what your repo really allows, sets up everything else and tells you exactly what's missing. Image signing works on Free private repos too, when pipegen can confirm the signing environment's branch rule (only your default branch may use the key).

## Commands *(planned)*

```bash
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo
                          # read-only report; run it from OUTSIDE the repo, exact version, explicit registry
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo --out report.md
                          # also save the report as a Markdown file, outside the repo
                          # (--json prints the report as JSON instead of text)
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo --ai
                          # also ask an AI for extra checks and tools to mention, after it shows what it would send
                          # and asks you (default No)
```

`audit --ai` needs Linux or macOS for now (WSL works): it checks your code for secrets with a pinned betterleaks binary
before anything is sent (or gitleaks, the fallback, when `PIPEGEN_SECRET_SCANNER` is set to `gitleaks`), and those
binaries exist for those systems only.

Later versions add the full job (one PR), then `finish` (after you merge: merge rules, signing key and dates), `verify`
(read-only: checks nobody weakened the pipeline files) and `uninstall`. Their exact commands will be shown here when
they exist; until then no other pipegen command is safe to copy, because the npm name isn't published yet.

## Read more

- [Design](docs/design.md)
- [Threat model](docs/threat-model.md): who could attack, and what stops them
- [Roadmap](docs/roadmap.md)

## Licence

[Apache-2.0](LICENSE).
