# pipegen Threat Model

> Version 5, 2026-10-27, for design v3.2 (adds what spikes S2 and S3 measured on real GitHub repos: T47 and T48, and a corrected T30; DECISIONS #73–#77). Version 4 added the user's-machine threats T40–T45 and the milestone map. Plain English. It's updated whenever the design changes. v2 adds the threats found by the round-2 red team (T17–T27) and corrects T1 and T8.

## What we protect (assets)

| Asset | Why it matters |
|---|---|
| The user's **source code** | It's private and the company's main value |
| The user's **secrets** (API keys, test keys, the signing key, the Slack webhook) | A leak gives an attacker access to systems |
| The user's **CI** (what runs in their GitHub Actions) | Code that runs there can steal secrets or tamper with builds |
| The user's **GitHub account access** (the token pipegen uses) | Too much access = everything can be changed |
| The **gate decision** | If it can be faked, bad code reaches `main` or production |
| **pipegen's own releases**, reviewed list and gate action | One compromise reaches **every** user at once |

## Who could attack (actors)

1. **A malicious tool author / typosquatter**: publishes a tool or action with a name close to a popular one, or buys stars.
2. **A hijacked maintainer** of a real tool: moves a tag to a malicious commit (the tj-actions case, March 2025).
3. **A malicious contributor to the user's repo**: puts hidden instructions in code or docs to steer the AI (prompt injection), or opens a PR that fakes a passing check.
4. **An attacker targeting pipegen itself**: compromises pipegen's npm package, repo, reviewed list or gate action.
5. **A curious insider / mistake**: pastes production keys as "test" keys, or closes the setup PR halfway.

## Entry points and threats → what stops them

| # | Threat | Mitigation in v3 | Residual risk |
|---|---|---|---|
| T1 | The AI is steered into choosing a malicious tool | Blocking tools come **only from the reviewed list**. Live finds are **mention-only** (never run). Security-relevant inputs are fixed by templates, and the AI picks only enums | A reviewed tool that is itself compromised (T3, T26) |
| T2 | Typosquatted or star-farmed tool | Near-duplicate name check against the reviewed list. The quality bar (Scorecard, age, licence, advisories). Unreviewed tools are mention-only (never run) | A new, clean-looking malicious tool can still pass the bar → it's only ever mentioned, never run |
| T3 | A tag moved to a malicious commit | Pins are full SHAs. **A moved tag → stop + alert**, never auto-update. The watcher flags moved tags as urgent | A commit that was malicious from the start and got reviewed (needs maintainer review to slip) |
| T4 | Prompt injection makes the AI write a dangerous command | `StepSpec` validation, no free YAML, referee + actionlint + zizmor, reviewed templates for blocking steps (security-relevant inputs fixed), unreviewed tools never run, change guard (no app code edits) | AI-chosen enum values within reviewed templates |
| T5 | Over-powered token | GitHub App or fine-grained token limited to the involved repos. Classic broad tokens refused by default | The user can override with `--allow-broad-token` |
| T6 | Code copied into the scratch repo leaks old secrets from history | **HEAD only, no history**. A private per-project scratch repo. Emptied after proof | Secrets still present in current files (pipegen's own secret scan warns about them in the audit and before the proof) |
| T7 | User workflows run in the scratch repo (deploys, webhooks, cloud OIDC) | **All** user workflows are disabled in scratch. Existing jobs are run only as pipegen-controlled copies without the user's secrets | Cloud trust policies that trust `repo:owner/*` → the README advises pinning OIDC trust to exact repos |
| T8 | A faked passing gate (same-name check) | Verify-first checks: the run of `pipegen.yml`, `event == push`, the same repository, the expected central SHA in `referenced_workflows`, gate job success. The public key comes from the `pipegen-signing` environment variable and must match its hash in the install record (T30). Spike S2: the gate is found through the run's jobs, and `referenced_workflows[].ref` is missing when the central workflow is pinned by SHA (DECISIONS #78) | Runs past retention can't be verified (fails closed) |
| T9 | Gate fails open (no baseline, forks) | No baseline → a **same-run base-commit scan** decides what's new (dependency and image findings always). Fingerprints count occurrences. Secret fingerprints are an HMAC per secret | Scanners that can't run on the base commit only warn on installing PRs |
| T10 | The signing key is readable from any branch | Environment secret limited to the default branch. **No signing on Free private** (honest) | An admin can change the environment rules |
| T11 | Secrets leak through logs, AI, PRs, Slack | Never written. Redaction (incl. connection strings) before the AI. Masking in CI. Values wiped from memory after storing | A tool printing a secret in its own logs (CI masking covers registered secrets) |
| T12 | Production keys pasted as test keys | The question says "test keys only". Keys are deleted from scratch after proof. They're stored in the app repo only if the user confirms | The user ignores the warning |
| T13 | Made-up packages (hallucinated deps) | Every added package must exist in its registry and pass the quality bar | A real but malicious package that passes the bar (rare, possible) |
| T14 | Compromise of pipegen's releases or reviewed list | Trusted publishing + provenance, signed tags, rulesets, CODEOWNERS on `data/reviewed-tools.yml` and `gate/`, Scorecard 9+ goal, a second maintainer | A single-maintainer period before a second maintainer joins |
| T15 | The setup PR is closed without merging and a required check blocks the repo | Settings are applied **only after merge** | None known |
| T16 | Runaway costs (Actions minutes, AI) | Estimates at consent, a hard 2× minutes cap, a monthly estimate in `PIPEGEN.md`, audit first | Estimates can be off for unusual repos |


### Added in version 2 (round-2 red team)

| # | Threat | Mitigation in v3.1 | Residual risk |
|---|---|---|---|
| T17 | **A PR rewrites the workflow or scanner config that judges it** (GitHub runs the PR's own workflow files) | The gate blocks PRs touching protected paths unless a CODEOWNER approved. New suppressions are findings. Code-owner review in the ruleset (≥ 2 writers). **Org required workflow** on Team/Enterprise orgs. `pipegen verify` reports drift | **Solo/personal repos:** someone who can merge can weaken the pipeline. It's visible, but it can't be prevented |
| T18 | **Artifact poisoning:** a job uploads a fake "clean" SARIF that the gate trusts | Exact artifact names only. The SARIF sha256 is checked against the producing job's output. Advisory tools use a separate prefix | A compromised **reviewed** tool can still lie (reviewed-list governance) |
| T19 | **Baseline / clean-run spoofing** from a fork branch named `main` | Accepted only from `push` runs of `pipegen.yml` in the same repository id, with the run id stored in the artifact | None known |
| T20 | **Cache poisoning** by a PR job or another workflow, read later by a gate-feeding, build or sign job | `cache-mode: none` on every job that feeds the gate or builds, signs or verifies; scanners' own caches off | Caches in the user's own jobs stay outside pipegen's control |
| T21 | **Scratch push race:** user workflows fire on push before they're disabled | User workflow files are never pushed (compat copies only). Secrets are stored after that. Egress is limited in proof | None known |
| T22 | **The AI adds code that runs in CI** (scripts, dependencies, tests, Dockerfile), steered by injected text in logs | Fixes are limited to the failing part's files. Script and dependency changes get a separate confirmation. `--ignore-scripts`. No advisory logs in prompts. No secrets for created code beyond the runtime env. Egress limited in proof | A real but malicious package that passes the quality bar |
| T23 | **Secrets in scan artifacts** (scanners copy the found key into the report) | `--redact`, snippets stripped after hashing, scratch runs and artifacts deleted after proof | Logs of user-owned jobs |
| T24 | **Hostile repo content attacks the CLI machine** (symlinks to `~/.aws/credentials`, path tricks) | `lstat`, symlinks never followed, every resolved path checked to stay inside the project | Bugs in archive/parsing libraries |
| T25 | **Token scope not verified** (a fine-grained token may push users to "All repositories") | The user creates the helper repos, and the token is scoped to exactly 3 repos. Spike S1 confirms before build | Decided by S1 |
| T26 | **Platform actions or images move** (checkout, upload-artifact, base images) | In the reviewed list with stored SHAs/digests and moved-tag alerts | Same as T3 |
| T27 | **Release hijack** (a stolen maintainer account publishes a bad version, or `npx pipegen` runs whatever is latest) | Tag ruleset, trusted publishing, exact-version instructions (`npx pipegen@x.y.z`, `npm audit signatures`), a 7-day cooldown for gate/watcher/list bumps, a second maintainer goal | A single-maintainer period |

### Added in version 3 (third review)

| # | Threat | Mitigation in v3.2 | Residual risk |
|---|---|---|---|
| T28 | **A commit status fakes the required check** (`POST /statuses`, no file change) | The required check `pipegen / gate` is bound to the GitHub Actions app (`integration_id` 15368). Spike S2 confirmed that a commit status with the same name can't satisfy the bound check, and that without the binding it can, so the binding is required (DECISIONS #73) | Another Actions job with the same name also comes from that app (T47) |
| T29 | **Stale approval:** a harmless commit is approved, then a malicious one is pushed | `dismiss_stale_reviews_on_push`, `require_last_push_approval`, approvals counted only on the head SHA, approvals re-run the gate | None known |
| T30 | **Writable variables and secrets:** anyone with write access can overwrite repo **and environment** variables and secrets, including those of the `pipegen-signing` environment (`PIPEGEN_COSIGN_PUB`, `PIPEGEN_COSIGN_KEY`, `PIPEGEN_FP_KEY`, `PIPEGEN_BLOCK_FROM`), and can disable workflows (spike S3). So they could swap the signing key or move the block date | These values are **not a trust root**. The gate and verify steps compare each one against the hash recorded at install time in the owner-controlled central `pipelines` repo (CODEOWNERS-protected, T33), and a mismatch is a finding (DECISIONS #76). A disabled pipegen workflow is a watcher finding | A swapped value is caught at the next gate or verify run, not when it is written. Block-date tampering only delays blocking of old findings. Central admins (T33) |
| T31 | **Verify-first checks the wrong commit** (`workflow_run`, dispatch with a ref) | The SHA comes from what is deployed. Unsupported triggers get no verify job and are listed as a gap | Deploys outside GitHub Actions |
| T32 | **AI-changed code runs with real test keys** (prompt injection through logs) | Placeholder secrets first, confirmation before real keys, code-extracted log excerpts, egress limited | A user who confirms without reading |
| T33 | **Tampering with the central repo** (malicious reusable workflows, edited install records) | A ruleset + CODEOWNERS on central, the install-record hash kept locally and in the PR body, `verify` | Central admins |
| T34 | **A tag named like a branch** passes trusted-run filters | Branch-only push triggers, and `head_sha` must be in the default branch's history | None known |
| T35 | **Abusing `not-proven`** to switch off the gate | Floor needs can never be not-proven (built into the gate). For private repos, the list lives in central | Non-floor needs marked not-proven by a code owner |
| T36 | **Scanner config auto-loaded from the repo** turns rules off | Explicit pinned configs, and declared config/ignore files are protected paths | Scanners with undocumented auto-load files (handled by review) |
| T37 | **Compat copies reach real infrastructure** (self-hosted runners, OIDC) | GitHub-hosted runners only, no `id-token`, `environment` or secrets, `contents: read` | None known |
| T38 | **The scratch repo is visible to org members** | Base-permission check and warning, delete after proof when possible, HEAD only | An org admin |
| T39 | **Runaway AI cost** | Estimate split into input/output, a hard AI cost cap (2×), prompt caching, rule-based failure classification | Estimates can be off for unusual repos |

### Added in version 5 (spikes S2 and S3, measured on real repos)

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T47 | **A same-name fake gate job:** a PR removes the real gate job and adds its own job named `pipegen / gate`. Every job in GitHub Actions comes from the same app (15368), so the app binding of T28 doesn't tell them apart; in spike S2 such a PR merged | A fake job can't override a failed real gate, so the attack needs the real gate removed, which changes `.github/workflows/**`. The guard is **code-owner review of `.github/workflows/**`**: CODEOWNERS plus required code-owner review are part of the floor wherever the plan allows (DECISIONS #75). The required gate check sits in its own gate-only ruleset with **no bypass**, separate from the PR-rules ruleset that carries the admin bypass for one-writer teams, so an admin bypass never skips the gate (DECISIONS #74). Verify-first finds the gate through the run of the central workflow (workflow path, `head_sha`, `event=push`, `referenced_workflows`, then the run's jobs, DECISIONS #78), not by check name | **Free private repos** have no rulesets, so there is no required code-owner review: there this is a documented limit. Solo repos: whoever can merge can also do this (T17) |
| T48 | **Capabilities assumed from the plan name:** pipegen assumes a protection exists that GitHub doesn't enforce, or skips one it does. Spike S3 found that private Free repos **do** have environments, environment secrets and variables, and deployment branch policies (against GitHub's docs), but **not** required reviewers, wait timers or attestations (422) | Capability detection **probes** each feature on the repo, never infers it from the plan name: a 422 "billing plan" answer means unavailable, and a code-scanning 404 "no analysis found" means available (DECISIONS #77). Only what the probe confirmed is relied on | GitHub can change what each plan allows without notice; probing (rather than a table of plans) keeps pipegen correct, but a change after the probe isn't seen until pipegen probes again |

### The user's machine running the CLI (v0.1 audit and every later command)

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T40 | **A compromised dependency of pipegen** runs on the user's machine (`npx` resolves version ranges) | All dependencies are **bundled** into `dist` (zero runtime `dependencies`), trusted publishing, a 7-day cooldown for build dependencies | A compromised build-time dependency at release time (cooldown + review) |
| T41 | **A hostile repo redirects `npx`** (its own `.npmrc` registry, or a local `node_modules/.bin/pipegen`) | Run from outside the repo with `--dir` and an explicit `--registry`. The audit warns about a registry `.npmrc` or a local pipegen binary | A user who ignores the instructions |
| T42 | **`--out` writes through a symlink** (e.g. into `~/.bashrc`) | No-follow + exclusive create, symlinks refused, default output location outside the repo | None known |
| T43 | **Terminal / Markdown injection** from repo-controlled names (ANSI/OSC escape codes, bidi, links) | Every repo- or AI-derived string goes through `safeText`/`safeMarkdown` | New terminal features (regular fixture updates) |
| T44 | **Parser or regex denial of service** (YAML alias bombs, huge files, very long lines) | 1 MB file limit, 20k file limit, `maxAliasCount`, line-length limit for regexes, no child processes during the audit without `--ai`; with `--ai`, only the pinned, checksum-verified gitleaks binary | Slow but bounded runs on huge repos |
| T45 | **Token leak** (sent to a wrong host, printed in errors or JSON) | Hard-coded `api.github.com`, never printed, tests on `--json`/`--out` | None known |
| T46 | **AI key leak** (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` sent to a wrong host, or shown in errors) | Keys are read only from the environment pipegen is given, never from the repo. Claude uses a hard-coded `https://api.anthropic.com` (`ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` are ignored), OpenAI a hard-coded `https://api.openai.com/v1/chat/completions`, and Ollama gets no key. Error messages are pipegen's own text, never a response body (OpenAI echoes part of a wrong key). Tests build keys at runtime and check every error. The Anthropic SDK's OpenTelemetry tracing is turned off in code (no spans, no trace headers), so a tracer the user has loaded can't export prompts that hold repo code | The Anthropic SDK also adds the headers listed in the user's own `ANTHROPIC_CUSTOM_HEADERS` variable to every Claude request, and it has no switch to turn that off. Those headers still go only to `api.anthropic.com`, and they come from the user's environment, not the repo |

### Which threats matter in which milestone

- **v0.1 (audit):** T5, T11, T14, T24, T27, T39 (with `--ai`), T40–T46 (T46 with `--ai`).
- **v0.2 (full run):** all of the above, plus T1–T4, T6–T10, T12, T13, T15–T23, T25, T26, T28–T38, T47, T48.
- **v0.3:** adds the watcher- and Slack-specific parts of T3, T26, T33.

## Out of scope (v3)

Malicious GitHub staff or infrastructure. A compromised user machine. Attacks on the AI providers themselves. Making a malicious repo look clean on purpose (pipegen protects pipelines, it doesn't certify code).

## Review rule

Any change to the reviewed list, the gate, token handling, or what runs in CI updates this file in the same PR.
