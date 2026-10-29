# pipegen audit: acme/shop-api

Audited commit: f4bcfab on branch main.

Audited on 2026-10-27. pipegen changed nothing in the repo or on GitHub. Nothing was sent to an AI.

**Verdict:** 4 of 4 layers have gaps; 4 are serious. pipegen couldn't check everything in 2 layers.

Scheduled and repo-file checks: gaps (0 of 3 checks covered).

## ⚠ Warnings

- ⚠ Secret-like text in the files on disk now, from a quick check for a few secret formats, not a secret scan (pipegen never shows the values):
  - .env: generic-api-key (never sent to the AI; check it isn't committed)
  - config/dev.json: aws-access-key, private-key
  - This check looks for private keys, a few known token formats (AWS, GitHub, Slack, Stripe, Google and npm tokens, and sk- API keys), JWTs, passwords inside connection strings, and file names that look like a secret.
  - It doesn't look for \`name = value\` lines, such as an API key or a password set in code, in a config file or in a .env file (in a .env file only a password inside a connection string is found), and any token format not listed. So this is not a secret scan: finding nothing here does not mean the repo holds no secrets.
  - \`pipegen audit --ai\` runs a full secret scanner (betterleaks, or gitleaks) on the files it would send, before anything is sent; the pipeline pipegen sets up (v0.2) runs betterleaks or gitleaks on every push and pull request.
- ⚠ This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:
  ```sh
  npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./repo
  ```

## What your GitHub plan allows

- ⚠ No merge lock: anyone with write access can merge without checks (GitHub Pro for personal accounts, GitHub Team for organisations, adds it).
- ⚠ Without a merge lock, a pull request could replace the gate with a fake one; only code-owner review stops it.
- ⚠ No deploy approvals: GitHub does not let this repo require a reviewer before a deploy.
- ⚠ No artifact attestations: GitHub does not offer them for this repo.
- ⚠ No code scanning: GitHub does not show scan results in the Security tab for this repo.

Available here: environments.

Repo: private, owned by a user account, GitHub plan: free.

## Checks by layer

### Before each commit (git hooks on the developer's machine): serious gaps (1 of 3 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
|   | covered | Git hook manager | The repo uses husky to run git hooks. | husky in .husky/pre-commit |
| ⚠ | missing | Secret scan | Without a secret scan before each commit, a key can be committed without anyone noticing. | — |
|   | missing | Format and lint hook for shop-api (warning only) | Without a format and lint hook, style problems are only found later, in CI or in review. | — |

### On every push: serious gaps (2 of 11 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Git hooks re-run in CI | Without running the hooks in CI, anyone who skips them locally is never caught. | — |
| ⚠ | missing | Secret scan | Without a secret scan in CI, a key committed without the local hook is only found after it leaks. | — |
| ⚠ | missing | Code scan (SAST) for shop-api | Without a code scan, common security bugs reach the main branch unnoticed. | — |
| ⚠ | partial | Dependency check for shop-api | npm-audit runs, but its failure is ignored (continue-on-error), so it can never fail the build. | npm-audit in .github/workflows/ci.yml (job audit) |
|   | covered | Unit tests for shop-api | Your own \`npm test\` runs on every push. | your own \`npm test\` in .github/workflows/ci.yml (job test) |
|   | covered | Lint for shop-api | Your own \`npm run lint\` runs on every push. | your own \`npm run lint\` in .github/workflows/ci.yml (job test) |
| ⚠ | missing | Type check for shop-api | Why type-check. | — |
| ⚠ | partial | Format check for shop-api | Why format. | — |
| ⚠ | partial | Test coverage minimum for shop-api | Why coverage. | — |
| ⚠ | partial | Dockerfile lint for shop-api | Why dockerfile-lint. | — |
| ⚠ | partial | Action pin check | Why workflow-pin-check. | — |

### On every pull request, before merge: serious gaps (2 of 15 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Secret scan | Without a secret scan in CI, a key committed without the local hook is only found after it leaks. | — |
|   | covered | Unit tests for shop-api | Your own \`npm test\` runs on every pull request. | your own \`npm test\` in .github/workflows/ci.yml (job test) |
|   | covered | Full test suite for shop-api | Your own \`npm test\` runs on every pull request. | your own \`npm test\` in .github/workflows/ci.yml (job test) |
|   | missing | Merge gate (pipegen) | No single required check sums up every scan, so a failing scan does not stop a merge. | — |
|   | unknown | Running-app scan (DAST) for shop-api | A job calls a reusable workflow from another repo, and pipegen can't see inside it. | acme/security/.github/workflows/zap.yml<U+200B>@<U+200B>v2 in .github/workflows/ci.yml (job zap) |
|   | missing | Copy-paste check (warning only) | Why duplication. | — |
|   | missing | Dead code and unused dependencies for shop-api (warning only) | Why dead-code. | — |
| ⚠ | missing | Workflow lint | Why workflow-lint. | — |
| ⚠ | partial | Format check for shop-api | Why format. | — |
| ⚠ | partial | Test coverage minimum for shop-api | Why coverage. | — |
| ⚠ | partial | Dockerfile lint for shop-api | Why dockerfile-lint. | — |
| ⚠ | partial | Action pin check | Why workflow-pin-check. | — |
| ⚠ | partial | New-dependency review | Why dependency-review. | — |
| ⚠ | partial | Licence check | Why licences. | — |
| ⚠ | partial | API scan against the spec (API DAST) | Why api-dast. | — |

### When the code is deployed or released: serious gaps (0 of 4 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Software bill of materials (SBOM) for shop-api | Without an SBOM, nobody can tell later which components a release shipped. | — |
|   | missing | Deploy check (pipegen) for shop-api | Deploys don't check that the commit passed the pipeline. | — |
|   | unknown | Trusted publishing | Why publishing. | — |
|   | unknown | Network lock for release jobs | Why egress. | — |

### On a schedule and in repo files: gaps (0 of 3 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
|   | missing | Dependency update config (warning only) | Why update-config. | — |
|   | missing | OpenSSF Scorecard (warning only) | Why scorecard. | — |
|   | missing | Fuzzing (built in v0.3) for shop-api (warning only) | Why fuzzing. | — |

## Checks that don't apply here

- no services found
  - Format check
  - Test coverage minimum
- no Dockerfile found
  - Dockerfile lint (for shop-api, worker)

## What pipegen would add

For each check that isn't covered:

- Secret scan, before each commit (now missing): gitleaks v2.3.9 (gitleaks/gitleaks-action), reviewed tool
- Format and lint hook for shop-api, before each commit (now missing): no reviewed tool yet; pipegen would only mention one, never run it as a check
- Git hooks re-run in CI, on every push (now missing): no reviewed tool yet; pipegen would only mention one, never run it as a check
- Secret scan, on every push (now missing): gitleaks v2.3.9 (gitleaks/gitleaks-action), reviewed tool
- Code scan (SAST) for shop-api, on every push (now missing): semgrep 1\.95.0 (semgrep/semgrep), reviewed tool
- Dependency check for shop-api, on every push (now partial): no reviewed tool yet; pipegen would only mention one, never run it as a check
- Secret scan, on every pull request (now missing): gitleaks v2.3.9 (gitleaks/gitleaks-action), reviewed tool
- Merge gate (pipegen), on every pull request (now missing): pipegen's own check. On this plan GitHub can't make it a required check, so it reports but can't block a merge
- Running-app scan (DAST) for shop-api, on every pull request (now unknown): no reviewed tool yet; pipegen would only mention one, never run it as a check
- Software bill of materials (SBOM) for shop-api, at deploy (now missing): no reviewed tool yet; pipegen would only mention one, never run it as a check
- Deploy check (pipegen) for shop-api, at deploy (now missing): pipegen's own check
- Type check for shop-api, on every push (now missing): your own `tsc` 7\.0.2 (from your lockfile) would run here; tsc is in the lockfile
- Copy-paste check, on every pull request (now missing): jscpd 5\.4.2 (kucherenko/jscpd), jscpd: finds copy-pasted code; warning only
- Dead code and unused dependencies for shop-api, on every pull request (now missing): knip 5\.50.0 (webpro-nl/knip), Knip: finds unused files
- Dependency update config, on a schedule (now missing): pipegen would write \`.github/dependabot.yml\`
- OpenSSF Scorecard, on a schedule (now missing): OpenSSF Scorecard: scores the repo weekly
- Fuzzing (built in v0.3) for shop-api, on a schedule (now missing): pipegen builds fuzzing in v0.3
- Workflow lint, on every pull request (now missing): actionlint 1\.7.12 (rhysd/actionlint), plus zizmor 1\.31.1 (zizmorcore/zizmor), actionlint and zizmor: check the workflows

pipegen would also create:

- Dockerfile: shop-api runs but has no Dockerfile: pipegen would create one, so the image can be built and scanned.
- Compose file: The app uses postgres: pipegen would create a Compose file that starts them for the tests.

## After the setup PR is merged, pipegen would turn on:

- Require actions pinned to a commit: Makes GitHub refuse any action that is not pinned to a commit.
- Dependabot alerts: Tells you when a dependency has a known vulnerability.
- Secret scanning: A paid add-on (GitHub Secret Protection); pipegen can't turn it on here.

## Costs of the full setup (estimates)

- Setup: about 70 GitHub Actions minutes, with a hard limit of 140 (the setup stops there).
- After setup: about 1,240 minutes a month, or more (pipegen could count only part of the activity).
  - ⚠ That is more than half of the 2,000 minutes your plan includes each month (62%).
- AI: input <U+200B>\$1.20–<U+200B>\$3.60, output <U+200B>\$0.90–<U+200B>\$2.70 (total <U+200B>\$2.10–<U+200B>\$6.30); pipegen stops calling the AI at <U+200B>\$12.60.
- Time: about 12–24 minutes.

How these estimates were made:

- Setup runs the pipeline for 2 proof variants (the real changes, and the same with planted problems), plus 30% for re-runs (× 1.3).
- Activity: at least 300 pushes and at least 41 pull requests in the last 30 days (GitHub lists only the last 300 events and pipegen reads at most 1,000 pull requests).
- Your free plan has 2,000 included minutes a month for private repos (docs.github.com, checked 2026-10-26).
- The AI cost cap is twice the high estimate (<U+200B>\$12.60); pipegen stops calling the AI there.

## What the full setup would send to the AI

pipegen would send 142 files (about 421 KB) to the AI.

Top folders: src, test, scripts.

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

- Contents: read and write — Opens the pull request with the pipeline files.
- Workflows: read and write — Adds the pipeline workflow files.

## Notes

- The quick secret check did not check dependency and build folders (node\_modules, .venv, dist, build, vendor, target) or .git, so committed build output was not checked either.
- pipegen reads the files on disk without git, so files that aren't committed (for example a local .env) are in this list too.

## What this audit can't see

- pipegen checks that a tool runs on the right trigger and can fail the build; it doesn't check the tool's other settings.
- Workflows limited by `paths:` or `paths-ignore:`, and jobs or steps with an `if:` condition, show as partial: pipegen can't tell when they run.
- A tool and a test joined on one line, like `{ tool; [[ … ]] } || true`, can hide a failing tool, and pipegen may still count it as covered (rare).
- Commands inside `bash -c '…'` or a quoted `"$(…)"` aren't read, so a tool run there shows as partial or missing.
- A `runs-on` set by an expression is read as Linux.
- Tools inside shell functions, and jobs whose matrix includes Windows, show as partial.
- Very large repos show some checks as unknown: past 200 workflow files, 100 jobs in a workflow, 200 steps in a job or action, 100 local workflows and actions followed, 16 MB of run text, 50,000 steps visited in all, 100,000 tool findings, 10,000 folders with runs, or 5,000 services.
- Reusable workflows from other repos, and actions from your own account, can't be looked inside: those checks show as unknown.
- Shell tricks such as `trap … EXIT`, `alias`, or a function named like the test tool aren't modelled, so a repo built to fool the audit could make a check look covered.
- A local action or reusable workflow that calls another local one isn't followed past the first level, so those checks show as unknown.
- `tox` counts as your own test run whatever environments its config lists: pipegen doesn't read tox's env_list.
- A tox or nox run whose environments a TOX… or NOX… variable in the job picks (like TOXENV from a matrix) shows as partial: pipegen doesn't read the variable's value, so it can't tell if the tests run.
- Variables that change what runs (SKIP for pre-commit, TOX… and NOX… for tox and nox, NPM_CONFIG_DRY_RUN) aren't seen when an action from another repo sets them, or when a step writes them under a name built while it runs.
- Dockerfile RUN lines count only when a `docker build`, docker/build-push-action or `docker compose build` step names the Dockerfile with plain paths, and only for the stages the final stage (or the target) needs. Build arguments, Compose profiles, `extends` and `include` aren't read.
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
- The quick secret check on the files on disk looks only for a few secret formats (private keys, some token formats, JWTs, passwords in connection strings); it doesn't read `name = value` lines, such as an API key or a password set in code or in a .env file, so it is not a secret scan.
- Kubernetes manifests are looked for only in YAML under folders named k8s, kubernetes, manifests, deploy, helm or charts (and a Chart.yaml anywhere), so manifests kept elsewhere, like infra/, aren't seen.

## Next step

The full setup arrives in v0.2 for single-package Node/TypeScript repos.
