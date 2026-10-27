# pipegen audit: acme/shop-api

Audited on 2026-10-27. pipegen changed nothing in the repo or on GitHub. You ran it with --ai: the AI part below says what the AI step found.

**Verdict:** 4 of 4 layers have gaps; 4 are serious. pipegen couldn't check everything in 1 layer.

## ⚠ Warnings

- ⚠ Secret-like text in the files on disk now (pipegen never shows the values):
  - .env: generic-api-key (never sent to the AI; check it isn't committed)
  - config/dev.json: aws-access-key, private-key
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
|   | missing | Format and lint hook for shop-api | Without a format and lint hook, style problems are only found later, in CI or in review. | — |

### On every push: serious gaps (2 of 6 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Git hooks re-run in CI | Without running the hooks in CI, anyone who skips them locally is never caught. | — |
| ⚠ | missing | Secret scan | Without a secret scan in CI, a key committed without the local hook is only found after it leaks. | — |
| ⚠ | missing | Code scan (SAST) for shop-api | Without a code scan, common security bugs reach the main branch unnoticed. | — |
| ⚠ | partial | Dependency check for shop-api | npm-audit runs, but its failure is ignored (continue-on-error), so it can never fail the build. | npm-audit in .github/workflows/ci.yml (job audit) |
|   | covered | Unit tests for shop-api | Your own \`npm test\` runs on every push. | your own \`npm test\` in .github/workflows/ci.yml (job test) |
|   | covered | Lint for shop-api | Your own \`npm run lint\` runs on every push. | your own \`npm run lint\` in .github/workflows/ci.yml (job test) |

### On every pull request, before merge: serious gaps (2 of 5 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Secret scan | Without a secret scan in CI, a key committed without the local hook is only found after it leaks. | — |
|   | covered | Unit tests for shop-api | Your own \`npm test\` runs on every pull request. | your own \`npm test\` in .github/workflows/ci.yml (job test) |
|   | covered | Full test suite for shop-api | Your own \`npm test\` runs on every pull request. | your own \`npm test\` in .github/workflows/ci.yml (job test) |
|   | missing | Merge gate (pipegen) | No single required check sums up every scan, so a failing scan does not stop a merge. | — |
|   | unknown | Running-app scan (DAST) for shop-api | A job calls a reusable workflow from another repo, and pipegen can't see inside it. | acme/security/.github/workflows/zap.yml<U+200B>@<U+200B>v2 in .github/workflows/ci.yml (job zap) |

### When the code is deployed or released: serious gaps (0 of 2 checks covered)

| | Status | Check | Why | Found |
|---|---|---|---|---|
| ⚠ | missing | Software bill of materials (SBOM) for shop-api | Without an SBOM, nobody can tell later which components a release shipped. | — |
|   | missing | Deploy check (pipegen) for shop-api | Deploys don't check that the commit passed the pipeline. | — |

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

pipegen would also create:

- Dockerfile: shop-api runs but has no Dockerfile: pipegen would create one, so the image can be built and scanned.
- Compose file: The app uses postgres: pipegen would create a Compose file that starts them for the tests.

### What the AI suggests (--ai)

- the AI also suggests checking type check for shop-api, on every push: The code is TypeScript; a type check catches mistakes the tests miss.

Tools the AI mentions (not reviewed, never run by pipegen):

- zizmor (woodruffw/zizmor): Finds risky settings in GitHub Actions workflows.

Notes from the AI step:

- In this version only GitHub Actions and npm packages can become suggestions.

AI cost of this audit: about <U+200B>\$0.42 at list price (2 AI calls; 41,200 input and 3,100 output tokens).

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

These are counts only, never file contents. They were made without the gitleaks check; before anything is sent, gitleaks checks every file for secrets and secret-looking values are hidden, so the real bundle can differ slightly.

## Permissions the full setup needs

- Contents: read and write — Opens the pull request with the pipeline files.
- Workflows: read and write — Adds the pipeline workflow files.

## Notes

- The secrets scan did not check dependency and build folders (node\_modules, .venv, dist, build, vendor, target) or .git, so committed build output was not checked either.
- pipegen reads the files on disk without git, so files that aren't committed (for example a local .env) are in this list too.

## What this audit can't see

- pipegen checks that a tool runs on the right trigger and can fail the build; it doesn't check the tool's other settings.
- A tool and a test joined on one line, like `{ tool; [[ … ]] } || true`, can hide a failing tool, and pipegen may still count it as covered (rare).
- Commands inside `bash -c '…'` or a quoted `"$(…)"` aren't read, so a tool run there shows as partial or missing.
- A `runs-on` set by an expression is read as Linux.
- Tools inside shell functions, and jobs whose matrix includes Windows, show as partial.
- Very large repos (over 10,000 folders with runs, or 5,000 services) show some checks as unknown.
- Reusable workflows from other repos, and actions from your own account, can't be looked inside: those checks show as unknown.

## Next step

The full setup arrives in v0.2 for single-package Node/TypeScript repos. It is not in this version; once v0.2 is out, it starts with:

```sh
npx pipegen
```
