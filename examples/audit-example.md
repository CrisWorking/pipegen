> **Real output.** This is the Markdown report `pipegen audit --out` wrote for the public repo [expressjs/express](https://github.com/expressjs/express) (commit `1c6f1b0`), unedited below this note. Run on 2026-10-29 with pipegen commit `4042eff` (v0.1 development branch, built with `npm run build`). It was an **anonymous** run: no GitHub token, so pipegen read public data only. The report says so itself, and its GitHub plan, code scanning and settings rows reflect that.

# pipegen audit: expressjs/express

Audited on 2026-10-29. pipegen changed nothing in the repo or on GitHub. Nothing was sent to an AI.

**Verdict:** 4 of 4 layers have gaps; 4 are serious. pipegen couldn't check everything in 1 layer.

Scheduled and repo-file checks: gaps (1 of 2 checks covered).

## ⚠ Warnings

- ⚠ Without a GitHub token, pipegen reads public data only and is rate-limited.

## What your GitHub plan allows

Nothing here limits the pipeline pipegen would build.

Available here: merge rules, environments, required deploy reviewers, artifact attestations, code scanning, keyless signing.

Repo: public, owned by an organisation, GitHub plan: not known (GitHub shows it only to the account's own token, or to an organisation member).

## Checks by layer

### Before each commit (git hooks on the developer's machine): serious gaps (0 of 3 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Git hook manager | Without a git hook manager, no check runs on a developer's machine before a commit. | — |
| ⚠ | missing | Secret scan | Without a secret scan before commit, a leaked key is in git history forever. | — |
|   | missing | Format and lint hook for express (warning only) | Without a format and lint hook, style problems are only found later, in CI or in review. | — |

### On every push: serious gaps (0 of 11 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Git hooks re-run in CI | Without running the hooks in CI, anyone who skips them locally is never caught. | — |
| ⚠ | missing | Secret scan | Without a secret scan in CI, a key committed without the local hook is only found after it leaks. | — |
| ⚠ | partial | Code scan (SAST) for express | The codeql check runs, but not on every push. | codeql in .github/workflows/codeql.yml (job analyze) |
| ⚠ | missing | Dependency check for express | Without a dependency scan, packages with known vulnerabilities ship unnoticed. | — |
| ⚠ | partial | Unit tests for express | Your own \`npm run test-ci\` runs, but not on every push. | your own \`npm run test-ci\` in .github/workflows/ci.yml (job test) |
| ⚠ | partial | Lint for express | Your own \`npm run lint\` runs, but not on every push. package.json asks for at least ESLint 8, and ESLint 8 reached end of life on 2024-10-05. | your own \`npm run lint\` in .github/workflows/ci.yml (job lint) |
| ⚠ | missing | Format check for express | No workflow or git hook in this repo runs this check. | — |
| ⚠ | partial | Test coverage minimum for express | Your own \`npm run test-ci\` runs, but not on every push. | your own \`npm run test-ci\` in .github/workflows/ci.yml (job test) |
|   | missing | Dead code and unused dependencies for express (warning only) | No workflow or git hook in this repo runs this check. | — |
| ⚠ | missing | Workflow lint | No workflow or git hook in this repo runs this check. | — |
| ⚠ | missing | Action pin check | No workflow or git hook in this repo runs this check. | — |

### On every pull request, before merge: serious gaps (3 of 16 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Git hooks re-run in CI | Without running the hooks in CI, anyone who skips them locally is never caught. | — |
| ⚠ | missing | Secret scan | Without a secret scan in CI, a key committed without the local hook is only found after it leaks. | — |
| ⚠ | partial | Code scan (SAST) for express | CodeQL reports findings but does not fail the job; they block only if code scanning merge protection is on. | codeql in .github/workflows/codeql.yml (job analyze) |
| ⚠ | missing | Dependency check for express | Without a dependency scan, packages with known vulnerabilities ship unnoticed. | — |
|   | covered | Unit tests for express | Your own \`npm run test-ci\` runs on every pull request. | your own \`npm run test-ci\` in .github/workflows/ci.yml (job test) |
|   | covered | Lint for express | Your own \`npm run lint\` runs on every pull request. package.json asks for at least ESLint 8, and ESLint 8 reached end of life on 2024-10-05. | your own \`npm run lint\` in .github/workflows/ci.yml (job lint) |
|   | covered | Full test suite for express | Your own \`npm run test-ci\` runs on every pull request. | your own \`npm run test-ci\` in .github/workflows/ci.yml (job test) |
|   | missing | Merge gate (pipegen) | No single required check sums up every scan, so a pull request with a failing scan can still be merged. | — |
| ⚠ | missing | Format check for express | No workflow or git hook in this repo runs this check. | — |
| ⚠ | partial | Test coverage minimum for express | This run measures test coverage, but pipegen hasn't checked for a minimum, so a drop in coverage may not fail it. | your own \`npm run test-ci\` in .github/workflows/ci.yml (job test) |
|   | missing | Dead code and unused dependencies for express (warning only) | No workflow or git hook in this repo runs this check. | — |
|   | missing | Copy-paste check (warning only) | No workflow or git hook in this repo runs this check. | — |
| ⚠ | missing | Workflow lint | No workflow or git hook in this repo runs this check. | — |
| ⚠ | missing | Action pin check | No workflow or git hook in this repo runs this check. | — |
| ⚠ | missing | New-dependency review | No lockfile is committed, so new-dependency review and licence checks can't run until one is. | — |
| ⚠ | missing | Licence check | No lockfile is committed, so new-dependency review and licence checks can't run until one is. | — |

### When the code is deployed or released: serious gaps (0 of 6 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Software bill of materials (SBOM) for express | Without an SBOM, nobody can tell later which components went into a build. | — |
| ⚠ | missing | Release signing for express | Without release signing, nothing proves that a published release came from this pipeline. | — |
| ⚠ | missing | Build attestation for express | Without an attestation, nothing records how and where the release was built. | — |
|   | missing | Deploy check (pipegen) for express | Deploys don't check that the commit passed the pipeline, so an unchecked commit can be deployed. | — |
|   | unknown | Trusted publishing for express | pipegen can't confirm trusted publishing from the workflow alone. Trusted publishing is set up on npmjs.com or PyPI, which pipegen can't see. | .github/workflows/npm-publish.yml |
| ⚠ | missing | Network lock for release jobs for express | No workflow or git hook in this repo runs this check. | — |

### On a schedule and in repo files: gaps (1 of 2 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
|   | partial | Dependency update config (warning only) | Dependabot's default wait is 3 days; pipegen uses 7. Set cooldown default-days to at least 7 (with no lower per-type days, include or exclude) on every entry. | dependabot in .github/dependabot.yml |
|   | covered | OpenSSF Scorecard (warning only) | The scorecard check runs on a schedule or on every push to the default branch. | scorecard in .github/workflows/scorecard.yml (job analysis) |

## Checks that don't apply here

- no tsconfig.json or typescript dependency found
  - Type check (for express)
- no Dockerfile found
  - Dockerfile lint (for express)
- this service doesn't run as a server, so there is nothing to call
  - API scan against the spec (API DAST) (for express)
- no fuzz targets found
  - Fuzzing (built in v0.3) (for express)
- no Terraform or Kubernetes files found
  - Infrastructure code scan (IaC)

## What pipegen would add

For each check that isn't covered:

- Git hook manager, before each commit (now missing): evilmartians/lefthook v2.2.2 (evilmartians/lefthook), reviewed tool
- Secret scan, before each commit (now missing): betterleaks/betterleaks v1.9.0 (betterleaks/betterleaks), Betterleaks: scans for committed secrets
- Format and lint hook for express, before each commit (now missing): your own \`lint\` script would run here
- Git hooks re-run in CI, on every push (now missing): evilmartians/lefthook v2.2.2 (evilmartians/lefthook), reviewed tool
- Secret scan, on every push (now missing): betterleaks/betterleaks v1.9.0 (betterleaks/betterleaks), Betterleaks: scans for committed secrets
- Code scan (SAST) for express, on every push (now partial): semgrep/semgrep 1\.181.0 (semgrep/semgrep), reviewed tool
- Dependency check for express, on every push (now missing): google/osv-scanner v2.7.0 (google/osv-scanner), reviewed tool
- Unit tests for express, on every push (now partial): your own \`test\` script would run here
- Lint for express, on every push (now partial): your own \`lint\` script would run here
- Git hooks re-run in CI, on every pull request (now missing): evilmartians/lefthook v2.2.2 (evilmartians/lefthook), reviewed tool
- Secret scan, on every pull request (now missing): betterleaks/betterleaks v1.9.0 (betterleaks/betterleaks), Betterleaks: scans for committed secrets
- Code scan (SAST) for express, on every pull request (now partial): semgrep/semgrep 1\.181.0 (semgrep/semgrep), reviewed tool
- Dependency check for express, on every pull request (now missing): google/osv-scanner v2.7.0 (google/osv-scanner), reviewed tool
- Merge gate (pipegen), on every pull request (now missing): pipegen's own check
- Software bill of materials (SBOM) for express, at deploy (now missing): anchore/syft v1.55.0 (anchore/syft), reviewed tool
- Release signing for express, at deploy (now missing): sigstore/cosign v3.1.3 (sigstore/cosign), reviewed tool
- Build attestation for express, at deploy (now missing): actions/attest v4.2.2 (actions/attest), reviewed tool
- Deploy check (pipegen) for express, at deploy (now missing): pipegen's own check
- Format check for express, on every push (now missing): prettier/prettier 3\.9.10 (prettier/prettier), Prettier: ESLint lints here, and it does not format
- Format check for express, on every pull request (now missing): prettier/prettier 3\.9.10 (prettier/prettier), Prettier: ESLint lints here, and it does not format
- Test coverage minimum for express, on every push (now partial): bcoe/c8 12\.0.0 (bcoe/c8), c8: the test runner has no coverage of its own; minimum: \`floor(current) - 1\`; 60% of lines for repos with few tests; an existing minimum is kept
- Test coverage minimum for express, on every pull request (now partial): bcoe/c8 12\.0.0 (bcoe/c8), c8: the test runner has no coverage of its own; minimum: \`floor(current) - 1\`; 60% of lines for repos with few tests; an existing minimum is kept
- Dead code and unused dependencies for express, on every push (now missing): webpro-nl/knip 6\.42.1 (webpro-nl/knip), Knip: finds unused files, exports and dependencies; report-only on the first run
- Dead code and unused dependencies for express, on every pull request (now missing): webpro-nl/knip 6\.42.1 (webpro-nl/knip), Knip: finds unused files, exports and dependencies; report-only on the first run
- Copy-paste check, on every pull request (now missing): kucherenko/jscpd v5.4.2 (kucherenko/jscpd), jscpd: finds copy-pasted code; warning only; new copy-paste in the pull request only
- Workflow lint, on every push (now missing): rhysd/actionlint v1.7.12 (rhysd/actionlint), plus zizmorcore/zizmor v1.31.1 (zizmorcore/zizmor), actionlint and zizmor: check the workflows for mistakes and risky patterns
- Workflow lint, on every pull request (now missing): rhysd/actionlint v1.7.12 (rhysd/actionlint), plus zizmorcore/zizmor v1.31.1 (zizmorcore/zizmor), actionlint and zizmor: check the workflows for mistakes and risky patterns
- Action pin check, on every push (now missing): suzuki-shunsuke/pinact v5.0.0 (suzuki-shunsuke/pinact), pinact: checks that every action is pinned to a commit
- Action pin check, on every pull request (now missing): suzuki-shunsuke/pinact v5.0.0 (suzuki-shunsuke/pinact), pinact: checks that every action is pinned to a commit
- New-dependency review, on every pull request (now missing): google/osv-scanner v2.7.0 (google/osv-scanner), plus actions/dependency-review-action v5.0.0 (actions/dependency-review-action), OSV-Scanner: checks new dependencies against known vulnerabilities, plus GitHub dependency review
- Licence check, on every pull request (now missing): aquasecurity/trivy v0.76.0 (aquasecurity/trivy), Trivy licence scan: no licence tool configured
- Trusted publishing for express, at deploy (now unknown): trusted publishing (OIDC); no long-lived token
- Network lock for release jobs for express, at deploy (now missing): bullfrogsec/bullfrog v0.11.1 (bullfrogsec/bullfrog), Bullfrog: blocks unexpected network traffic in release jobs
- Dependency update config, on a schedule (now partial): keep your Dependabot config; set \`cooldown.default-days: 7\`

pipegen would also create:

- Pre-commit hooks: No git hook manager found: pipegen would set up pre-commit hooks that check each commit.

## After the setup PR is merged, pipegen would turn on:

- Require actions pinned to a commit: Makes GitHub refuse any action that is not pinned to a commit. pipegen turns it on only after your other workflows pin their actions to a commit. Today none of your 5 workflows use tag pins; pipegen can't see this setting with read access, so it can't say whether it is already on.
- Dependabot alerts: Tells you when a dependency has a known vulnerability; free on every repo. pipegen can't see this setting with read access, so it can't say whether it is already on.
- Secret scanning: Blocks pushes that contain a known secret format (push protection). pipegen can't see this setting with read access, so it can't say whether it is already on.

## Costs of the full setup (estimates)

- Setup: about 162 GitHub Actions minutes, with a hard limit of 324 (the setup stops there).
- After setup: about 1,679 minutes a month, or more (pipegen could count only part of the activity).
- AI: input ​\$0.72–​\$2.16, output ​\$0.81–​\$2.43 (total ​\$1.53–​\$4.59); pipegen stops calling the AI at ​\$9.18.
- Time: about 51–102 minutes.

How these estimates were made:

- Actions minutes per job are measured, not guessed: on a small Node + Postgres app on a private repo (spike S5, 2026-10-26) a job billed about 1.1 minutes. pipegen counts 1 min for quick jobs (hooks, lint, secrets, dependency scan, gate, nightly), 2 min for code scans, tests, the image build and image scan (and any job S5 did not measure), and 3 min for the running-app scans (DAST and API DAST). That is the measured time plus about 50% for bigger apps and the egress-control step; larger apps take longer. The workflow, Dockerfile, copy-paste, new-dependency and licence checks and Scorecard were not measured; pipegen counts them as 1 min each (API DAST as 3).
- Setup runs the pipeline for 2 proof variants (the real changes, and the same with planted problems), plus 30% for re-runs (× 1.3).
- The setup minutes include the proof harness, 8 min per variant (app start, hooks, tests run twice, a signing round trip and the verify-first lookup).
- Copies of your own workflow jobs, run in the proof to compare results, count 2 min each per variant (8 jobs here).
- The hard cap on setup minutes is twice the estimate (324 min); the proof stops there. The cap also covers the extra variants that disputes add.
- Pre-commit checks run on the developer's machine, so they use no Actions minutes.
- Scorecard runs weekly; counted nightly (leans high).
- Activity: at least 3 pushes and at least 64 pull requests in the last 30 days (pipegen couldn't read back to the start of the 30 days: GitHub lists only the last 300 events, pipegen reads at most 1,000 pull requests, and it stops at GitHub's rate limit).
- Monthly minutes: every push runs the push layer; every push to a branch with an open pull request also runs the merge layer; every merged pull request runs the deploy layer; the nightly scan runs 30 times.
- GitHub's event list doesn't say which pushes went to a branch with an open pull request, so pipegen approximates them: every push except one per pull request (its merge into the default branch), and at least one per pull request. Pushes to branches without a pull request count too, so this leans high. Every pull request opened is counted as merged.
- This is a public repo: GitHub Actions minutes on standard GitHub-hosted runners are free.
- Time: the setup minutes spread over about 4 jobs in parallel, plus 10 min of queueing; the high end is twice that.
- AI tokens per stage (input / output): needs 30k / 3k; debate 3 rounds of 40k / 6k; creators 60k / 20k; fix loop 5 attempts of 15k / 4k for each of 2 parts expected to need a fix.
- Prices for claude-opus-5-5: ​\$4 per million input tokens and ​\$20 per million output tokens (checked 2026-10-27).
- Input and output tokens are priced separately. The AI cost range is half to one and a half times the token estimate.
- The AI cost cap is twice the high estimate (​\$9.18); pipegen stops calling the AI there.

## What the full setup would send to the AI

pipegen would send 58 files (about 138 KB) to the AI.

That is as much as fits: the code reached its size limit, so the rest would not be sent.

Top folders: examples, test, .github.

Never sent (every pattern; one that starts with ! keeps a file):

- \*\*/.env\*
- !\*\*/.env.example
- !\*\*/.env.sample
- \*\*/.env\*/\*\*
- \*\*/\*.pem
- \*\*/\*.key
- \*\*/id\_rsa\*
- \*\*/id\_dsa\*
- \*\*/id\_ecdsa\*
- \*\*/id\_ed25519\*
- \*\*/\*secret\*
- \*\*/\*secret\*/\*\*
- \*\*/\*.tfstate
- \*\*/\*.tfstate.backup
- \*\*/\*.tfvars
- \*\*/\*.tfvars.json
- \*\*/.npmrc
- \*\*/.netrc
- \*\*/\*.p12
- \*\*/\*.pfx
- \*\*/\*.jks
- \*\*/kubeconfig
- \*\*/kubeconfig.\*
- \*\*/\*.kubeconfig
- \*\*/.kube/config
- \*\*/.kube/\*\*
- \*\*/.git-credentials
- \*\*/.aws/credentials
- \*\*/.aws/config
- \*\*/credentials.json
- \*\*/.pgpass
- \*\*/.pypirc
- \*\*/.docker/config.json
- \*\*/\*.env
- \*\*/\*.keystore
- \*\*/\*.ppk
- \*\*/\*.p8
- \*\*/.htpasswd
- \*\*/service-account\*.json
- \*\*/package-lock.json
- \*\*/npm-shrinkwrap.json
- \*\*/yarn.lock
- \*\*/pnpm-lock.yaml
- \*\*/bun.lockb
- \*\*/bun.lock
- \*\*/poetry.lock
- \*\*/uv.lock
- \*\*/Pipfile.lock
- \*\*/Cargo.lock
- \*\*/Gemfile.lock
- \*\*/composer.lock
- \*\*/go.sum
- \*\*/node\_modules/\*\*
- \*\*/.git/\*\*
- \*\*/.venv/\*\*
- \*\*/dist/\*\*
- \*\*/build/\*\*
- \*\*/vendor/\*\*
- \*\*/target/\*\*

These are counts only, never file contents. They were made without the secret scan; before anything is sent, a secret scan (betterleaks, or gitleaks as the fallback) checks every file and secret-looking values are hidden, so the real bundle can differ slightly.

## Permissions the full setup needs

- Metadata: read — Always required. Read repo details and rulesets.
- Contents: read and write — Read your code, push the setup branch and the proof branches.
- Workflows: read and write — Add and change files in .github/workflows.
- Pull requests: read and write — Open the setup PR and the proof PR, and close them.
- Actions: read and write — Watch proof runs, disable or enable workflows, delete proof runs and logs. Also needed to list environments.
- Secrets: read and write — Set the repo secrets the pipeline needs (values encrypted on your machine).
- Variables: read and write — Set Actions variables such as PIPEGEN\_BLOCK\_FROM.
- Environments: read and write — Set environment secrets and variables (for example the signing key).
- Administration: read and write — Apply the merge rules (rulesets), create the deploy and signing environments and their branch rules, and change Actions settings. With a token pipegen never creates or deletes repos; it empties the scratch repo instead.
- Checks: read (GitHub App only) — Read the gate check result. A fine-grained token can't have it, so in token mode pipegen reads workflow runs and jobs instead.

## Notes

- Versions of eslint in the repository root come from package.json ranges (the lowest version each allows), not from a lockfile: no lockfile was found.
- Couldn't check code scanning without a token; GitHub offers it on every public repo.
- The secrets scan did not check dependency and build folders (node\_modules, .venv, dist, build, vendor, target) or .git, so committed build output was not checked either.
- Left out 1 file that matches the excluded patterns (files that may hold secrets, lockfiles, dependency and build folders).
- Left out lower-priority files to keep the bundle under the size limit (150000 bytes): test/app.use.js, test/fixtures/blog/index.html, test/fixtures/blog/post/index.tmpl, test/fixtures/users/index.html, examples/auth/views/foot.ejs, examples/auth/views/head.ejs, examples/auth/views/login.ejs, examples/ejs/views/footer.html, examples/ejs/views/header.html, examples/ejs/views/users.html and 147 more.

## What this audit can't see

- pipegen checks that a tool runs on the right trigger and can fail the build; it doesn't check the tool's other settings.
- Workflows limited by `paths:` or `paths-ignore:`, and jobs or steps with an `if:` condition, show as partial: pipegen can't tell when they run.
- A tool and a test joined on one line, like `{ tool; [[ … ]] } || true`, can hide a failing tool, and pipegen may still count it as covered (rare).
- Commands inside `bash -c '…'` or a quoted `"$(…)"` aren't read, so a tool run there shows as partial or missing.
- A `runs-on` set by an expression is read as Linux.
- Tools inside shell functions, and jobs whose matrix includes Windows, show as partial.
- Very large repos show some checks as unknown: past 200 workflow files, 100 jobs in a workflow, 200 steps in a job or action, 100 local workflows and actions followed, 16 MB of run text, 50,000 steps visited in all, 100,000 tool findings, 10,000 folders with runs, or 5,000 services.
- Reusable workflows from other repos, and actions from your own account, can't be looked inside: those checks show as unknown.
- A local action or reusable workflow that calls another local one isn't followed past the first level, so those checks show as unknown.
- `tox` counts as your own test run whatever environments its config lists: pipegen doesn't read tox's env_list.
- A tox or nox run whose environments a TOX… or NOX… variable in the job picks (like TOXENV from a matrix) shows as partial: pipegen doesn't read the variable's value, so it can't tell if the tests run.
- Variables that change what runs (SKIP for pre-commit, TOX… and NOX… for tox and nox, NPM_CONFIG_DRY_RUN) aren't seen when an action from another repo sets them, or when a step writes them under a name built while it runs.
- A pre-commit hook pinned to a commit SHA (`rev:`) isn't checked to be a commit of the hook's own repo, so it could come from a fork.
- pipegen knows the PyPI publish action up to v1.14.3: a newer release pinned by its commit SHA shows as partial until pipegen is updated.
- A test or lint script whose runner pipegen doesn't know (like `node test.js`) is trusted by its name: pipegen only lowers it when the script clearly does nothing or can't fail.
- Coverage minimums in JS or TS config files (like jest.config.js or vitest.config.ts) are read as text: pipegen finds the setting but can't run the file, so it can't confirm the minimum.
- Renovate presets (`extends`) aren't followed, so a setting that comes from a shared preset isn't seen.
- Repo settings on GitHub (required checks, secret scanning, the default token permissions) aren't read, so pipegen can't say whether they are already on.
- A workflow without a `permissions:` block gets the repo's default token permissions, a setting pipegen can't see.
- A deploy workflow that uses no secret and no write grant isn't seen as a release.
- Network egress control (blocking unexpected traffic from release jobs) is only partly read on larger runners.
- Environment variables set by third-party actions aren't seen, so a check one of them turns off can show as covered.
- pipegen can't check yet that an ESLint config reads .vue, .svelte and .astro files (the parsers and plugins come in v0.2): such a repo never shows a clean pass for ESLint.
- Kubernetes manifests are looked for only in YAML under folders named k8s, kubernetes, manifests, deploy, helm or charts (and a Chart.yaml anywhere), so manifests kept elsewhere, like infra/, aren't seen.

## Next step

The full setup arrives in v0.2 for single-package Node/TypeScript repos.
