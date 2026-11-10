# pipegen v0.2: the live smoke test (checklist template)

This is the checklist of the one live session after Plan G. Nothing in it has been run. **Every result below starts as `not run`.** Only the live session, done together with Cristiano on real GitHub repositories, changes a result, and it writes what it saw (the date, the run link, a short note) in the same cell. A coding task never writes a pass here.

No Plan G test needs anything on this list. `test/cli-run-e2e.test.ts` runs the whole `pipegen run` flow on one machine against fakes (a fake GitHub, a fake git transport, a scripted AI and recorded run answers); this file is what only a real GitHub run, a real account, real minutes or a real key can show.

## What the live session runs on

- **Gate pin:** `pipegen-gate` **gate-v0.2.3**, commit `468dd79af999342fbd525d4dd6fbe57f7e47e375` (the G15b re-pin; the tag is local until the release pushes; `gate/dist/index.js` sha256 `9ab707b2…`). If `git diff 468dd79 -- gate/dist` is not empty on the build under test, stop: the pin is stale.
- **Scope:** v0.2 sets up repositories owned by `CrisWorking` only (`SCOPE_LINE`). The throwaway projects below belong to `CrisWorking`.
- **Public repo:** `CrisWorking/pipegen` is public (ruling G-P1), so public app repos can use the gate (S28 branch a): the "gate Actions-access" setting is not needed.
- **npm:** the name `pipegen` is claimed (2026-11-06); the release publishes `0.2.0`.
- **Projects:** a private throwaway Node + Postgres project with no Dockerfile and no tests, and a public throwaway one (same shape).
- **Second writer:** the alt account `CrisWorkAlt`, for the two-writer and code-owner checks.

## Accounts and money

| # | Check | Source | Result |
|---|---|---|---|
| A1 | a fine-grained token with the write table plus Issues read works (S12). v0.2 has no App login (DECISIONS #127; planned next) | pre-flight §6 | not run |
| A2 | the `pipelines` and `pipegen-proof-<app>` repos are created by hand with the `gh repo create … --private` commands pipegen prints, and they are private | pre-flight §6 | not run |
| A3 | an Actions-minutes budget of about 1,000 to 2,500 minutes is available | pre-flight §6 | not run |
| A4 | an Anthropic key is set in the environment of the run | pre-flight §6 | not run |
| A5 | the alt account `CrisWorkAlt` has write access to both repos (at least two writers) | pre-flight §6 | not run |

## Bootstrap (B8)

| # | Check | Source | Result |
|---|---|---|---|
| B1 | one maintainer run from source with `PIPEGEN_BOOTSTRAP_PROOFS=1` on the private throwaway project passes its proof | pre-flight §6, B8 | not run |
| B2 | a delegated review (DECISIONS #105) then raises `proofs` of the entries that passed in `data/reviewed-tools.yml` (data only, no gate re-pin) | pre-flight §6, B8 | not run |
| B3 | a plain run (no bootstrap switch) now offers those entries as reviewed | pre-flight §6, B8 | not run |

## Smoke test: Task 8 Step 5

The 17 lines of plan Task 8 Step 5 (plan lines 537 to 554), in order, on the private throwaway project unless the line says otherwise. Section "Public project" lists which lines the public throwaway project repeats.

| # | Check | Source | Result |
|---|---|---|---|
| 1 | consent shows the estimates | plan Task 8 Step 5 | not run |
| 2 | the helper repos are private, and the public project has a records-only `pipelines` | plan Task 8 Step 5 | not run |
| 3 | the public project's caller job `pipegen` calls `./.github/workflows/pipegen-merge.yml`, whose job is `gate`, and its check is named `pipegen / gate` (`GATE_CHECK_NAME`) | plan Task 8 Step 5, as built (G2/G43, S18) | not run |
| 4 | created files are proven | plan Task 8 Step 5 | not run |
| 5 | the mid-run confirmation appears before real keys are used | plan Task 8 Step 5 | not run |
| 6 | scratch secrets are gone before the preview | plan Task 8 Step 5 | not run |
| 7 | the setup PR passes its own gate (base-scan diff) [Review Focus 5] | plan Task 8 Step 5 | not run |
| 8 | the hook blocks a fake key locally | plan Task 8 Step 5 | not run |
| 9 | a PR with a fake key is blocked by the gate | plan Task 8 Step 5 | not run |
| 10 | a PR editing `pipegen.yml` without code-owner approval is blocked | plan Task 8 Step 5 | not run |
| 11 | a green commit status with the context `GATE_CHECK_NAME`, posted through the API, doesn't unblock a PR (the required check is bound to the Actions app, integration id 15368) | plan Task 8 Step 5, pre-flight §6 | not run |
| 12 | approving, then pushing a new commit, dismisses the approval; a new approval re-runs the gate | plan Task 8 Step 5 | not run |
| 13 | a branch with an open PR runs only the merge layer | plan Task 8 Step 5 | not run |
| 14 | `finish --print` prints commands and changes nothing; then `finish` applies locks (app + central), the central CODEOWNERS, signing and variables (`PIPEGEN_BLOCK_FROM`). Signing is applied only for a project that builds an image (has a Dockerfile): the plain throwaway project has none, so it signs nothing and this line checks the locks, the CODEOWNERS and the variables only; signing is checked in section "Signing on a private project" | plan Task 8 Step 5, pre-flight §6, G16 review F5 | not run |
| 15 | `verify` reports a hand-made drift | plan Task 8 Step 5 | not run |
| 16 | a nightly issue with a patch is applied by `pipegen update` as a PR (re-derived, S27) | plan Task 8 Step 5, pre-flight §6 | not run |
| 17 | closing an unmerged setup PR leaves the repo with no new rules (the N4 signing environment stays and is recorded, S11) | plan Task 8 Step 5, pre-flight §6 | not run |

Line 3 replaces the plan line "the public project is inline, and its check is named `GATE_CHECK_NAME`". That plan text is stale: a public project is not inline. Its caller calls the local `./.github/workflows/pipegen-merge.yml` (job `gate`), a two-level chain (G2/G43, ruling S18). The check itself stays; only its wording changed. The controller fixes the plan line in `pipegen-internal`.

Order: the version bump to `0.2.0` and the npm publish come before row 8, R1 and R2. The hook files `pipegen run` delivers name `pipegen@<the package version>` (`pipegen@0.1.0` in a build that has not been bumped), so on an unbumped or unpublished build row 8 and R2 would test a version that is not the build under test, and R1 needs the published package.

## Signing on a private project

A private project is signed with a key pair (key-env) only when its `pipegen-signing` environment carries the default-branch rule, and only once that rule has been read back. Ruling G-SIGN1 (G16 review F6): when there is no such environment yet, a first `pipegen run` on a private repository that builds an image makes it itself, after consent and before assembly (only a new one: an environment that is already there and that the probe could not prove is left as it is), reads it back with the default-branch rule, and only then re-derives the signing mode, so the first run signs. It fails closed: when the environment can't be made, or doesn't read back usable from the default branch only, the run stays unsigned (mode `none`) and says why ("Signing is off (mode none): …"). These rows need a private throwaway project that builds an image (has a Dockerfile) and has no `pipegen-signing` environment at the start.

| # | Check | Source | Result |
|---|---|---|---|
| SIGN-1 | a first run on a private project with a Dockerfile and no `pipegen-signing` environment signs: after consent the run says it made the environment `pipegen-signing` (default branch only) and read it back; before the setup pull request opens the environment exists with exactly one branch rule (the default branch); the install record says signing mode `key-env` and lists the environment as made by pipegen (`created: true`); after the merge and `finish`, the published image is signed and `cosign verify` with the public key in `PIPEGEN_COSIGN_PUB` passes ; the PUT answer for the new environment has `created_at` equal to `updated_at` (pipegen claims an environment only then; if GitHub answers otherwise, write it down: every first run would be unsigned) | ruling G-SIGN1, G16 review F6, `src/cli/run.ts` (`firstRunSigning`), `src/deliver/deliver.ts` (`makeRunSigningEnvironment`) | not run |
| SIGN-2 | a re-run after the environment exists signs (key-env): the published image is signed with the key pair the run stored (made in memory by `pipegen run`, stored by its delivery; `finish` sets `PIPEGEN_COSIGN_PUB`), and `cosign verify` with the public key in `PIPEGEN_COSIGN_PUB` passes | ruling G-SIGN1, G16 review F6, G2/G3 reports | not run |
| SIGN-3 | a first run on a private project whose `pipegen-signing` environment is already there but can't be proven (for example it lets any branch deploy; try it once more with the environment named `Pipegen-Signing`, since GitHub's environment names are case-insensitive) leaves that environment unchanged, prints "Signing is off (mode none)" with the reason, and delivers an unsigned pipeline | ruling G-SIGN1, `src/deliver/deliver.ts` (`makeRunSigningEnvironment`) | not run |
| SIGN-4 | a first run as in SIGN-1 shows, on the consent screen, that pipegen creates `pipegen-signing` before the proof; answering no at the preview deletes the environment again (the consent line says it is deleted again if the run stops before you confirm the preview) ("pipegen deleted the environment pipegen-signing it made earlier in this run") and it is gone from the repository settings | ruling G-SIGN1-R1, `src/deliver/deliver.ts` (`dropRunSigningEnvironment`) | not run |
| SIGN-5 | a first run as in SIGN-1 on a machine with no memory folder (`/dev/shm`) makes no environment, prints "Signing is off (mode none)" with the reason, and delivers an unsigned pipeline (the run is not refused) | ruling G-SIGN1-R2 (spec L4), `src/cli/run.ts` (`NO_MEMORY_SIGNING_OFF`) | not run |

## Public project

The public throwaway project is in scope: the pipegen repo is public (G-P1), so S28 branch (a) applies and a public app repo can use the gate from `CrisWorking/pipegen`.

| # | Check | Source | Result |
|---|---|---|---|
| P1 | the public project's run reaches the proof (`gateReachable` finds the gate at `468dd79`) and delivers the local chain: `pipegen.yml` calls `./.github/workflows/pipegen-merge.yml` | S28, G2/G43 | not run |
| P2 | the private `pipelines` repo of the public project holds only `installs/<repo>.json` and its CODEOWNERS (records only, no workflow) | S28, plan Task 8 Step 5 line 2 | not run |
| P3 | Step 5 lines 1, 4 to 15 and 17 are repeated on the public project, with the same results | plan Task 8 Step 5 | not run |
| P4 | the check a PR shows on the public project is `pipegen / gate` through the two-level chain, and a branch rule requiring it blocks a PR whose gate fails (spike S2 covered the central layout only) | G5 report (Live) | not run |
| P5 | caller job permissions for a local reusable workflow are enough (`actions: read`, `contents: read`, `pull-requests: read`) | G5 report (Live) | not run |

## G-specific API facts

| # | Check | Source | Result |
|---|---|---|---|
| G-1 | `storeEnvSecret` path: an environment secret reaches the called sign job (D5) | pre-flight §6, G3 | not run |
| G-2 | the environment branch-policy read-back works on a Free private repo | pre-flight §6 | not run |
| G-3 | `sha_pinning_required` works on a Free private repo | pre-flight §6, G8 | not run |
| G-4 | the classic protection `checks[{context, app_id}]` binding holds | pre-flight §6, G8 | not run |
| G-5 | key-env cosign sign and verify work end to end with `--tlog-upload=false` (and `--use-signing-config=false`) | pre-flight §6 | not run |
| G-6 | the nightly "finish missing" issue opens after 24 hours (or on a simulated merge date) | pre-flight §6 | not run |
| G-7 | the org required workflow and attest mode work on a Team or Enterprise org; if there is none, record "tested with fakes only" | pre-flight §6 | not run |

## D7-R7 acceptance

The isolated starter-test job runs the probes below as hostile tests on a real runner (probes f1b, f2, f3, o2, e1 and e3). Until all of them pass, `isolatedTestJob` stays false in the referee, the guard and `pipegen run`, and a run writes no starter tests (a project with no tests needs `--skip tests`). Only after that does a reviewed change flip the switch (S19).

| # | Check | Source | Result |
|---|---|---|---|
| D7-1 | probe f1b (`f1b-tohaveproperty-fnproto.test.ts`, Plan D D7 review r5) runs as a hostile test in the isolated job and reaches no secret, no network, no write token and no file outside the job | D7-R7, S19, plan Task G4 | not run |
| D7-2 | probe f2 (`f2-tohaveproperty-ctx.test.ts`) runs as a hostile test in the isolated job with the same result | D7-R7, S19 | not run |
| D7-3 | probe f3 (`f3-objectcontaining-runtime-key.test.ts`) runs as a hostile test in the isolated job with the same result | D7-R7, S19 | not run |
| D7-4 | the earlier probe o2 runs as a hostile test in the isolated job with the same result | D7-R7, S19 | not run |
| D7-5 | the earlier probe e1 runs as a hostile test in the isolated job with the same result | D7-R7, S19 | not run |
| D7-6 | the earlier probe e3 runs as a hostile test in the isolated job with the same result | D7-R7, S19 | not run |
| D7-7 | across the six probes: no secret is readable; network egress is blocked; the token has no write scope and the checkout has no persisted credentials; no file written by the job reaches a later job or the repo | D7-R7, plan Task G4 | not run |
| D7-8 | only after D7-1 to D7-7 pass, a reviewed change passes `isolatedTestJob: true` to `createStarterTests`, the referee (`createdInputs`) and the guard (`GuardCtx`); until then a run with a project that has no tests uses `--skip tests` | D7-R7, S19 | not run |

## Plan F list

From plan Task F's live checklist (plan lines 885 to 899).

| # | Check | Source | Result |
|---|---|---|---|
| F-1 | `git ls-tree` the pinned semgrep-rules folders | Plan F list | not run |
| F-2 | semgrep reports both SQL files at `error` | Plan F list | not run |
| F-3 | osv-scanner reports lodash 4.17.11 and PyYAML 5.3 at high or above | Plan F list | not run |
| F-4 | the Terraform scanner reports `main.tf` at high or above | Plan F list | not run |
| F-5 | recursive workspace globs don't install the planted manifest | Plan F list | not run |
| F-6 | no C1b placement is missed | Plan F list | not run |
| F-7 | noise from the planted files in the lint and type-check jobs (m6) | Plan F list | not run |

## Plan E list

From the Plan E ledger (10-proof-runner.md lines 341 to 347; Plan E progress lines 39 to 47, 62 to 70, 96, 119 to 128, 251).

| # | Check | Source | Result |
|---|---|---|---|
| E-1 | Ctrl-C under `npx` on Windows and macOS during the proof runs the cleanup hook and saves `interrupted`; `pipegen resume` then works | Plan E list, G14 | not run |
| E-2 | askpass on Windows | Plan E list | not run |
| E-3 | case-insensitive `--dir` | Plan E list | not run |
| E-4 | Bullfrog hosts: the artifact blob host, `raw.githubusercontent.com` for setup-node, about ten action egress entries, Sigstore, the Trivy DB and `api.osv.dev` | Plan E list | not run |
| E-5 | docker-cp scanners (semgrep, ZAP) under Bullfrog | Plan E list | not run |
| E-6 | org repo creation, org roles, owners and invitations reads, `allow_forking`, org fork-PR secrets | Plan E list | not run |
| E-7 | the org-secrets list for a user-owned scratch repo | Plan E list | not run |
| E-8 | `GET /environments` on Free private | Plan E list | not run |
| E-9 | deleting an in-progress run | Plan E list | not run |
| E-10 | the code-scanning delete order | Plan E list | not run |
| E-11 | the 15-second minutes read | Plan E list | not run |
| E-12 | the letter `ſ` (U+017F) in secret names | Plan E list | not run |

## Live items by task

Every "Live" line of the Plan G ledger, under its source report (`task-G*-report.md`) or `progress.md`. The G15a items have their own section below.

| # | Item | Source | Result |
|---|---|---|---|
| L-G0-1 | a real scratch repo whose default branch is not `main`: after the base push, one PATCH; and a freshly created one (`defaultBranchState: 'pending'`) | G0 report, G14 report | not run |
| L-G0-2 | the first live run sets `PIPEGEN_BOOTSTRAP_PROOFS=1` on a dev build and a delegated review raises `proofs` (see Bootstrap) | G0 report | not run |
| L-G1-1 | `biome check --staged` works without `vcs.enabled` in the repo's biome config; if it needs it, the reviewed VCS flags are added (m6) | G1 report, G6 report | not run |
| L-G2-1 | the docker driver keeps the build-push image in the store with no `load` input | G2 report | not run |
| L-G2-2 | `docker image save` followed by trivy `--input` and syft `docker-archive:` works on a real runner; archive size and upload time are acceptable | G2 report | not run |
| L-G2-3 | `cosign sign --oidc-provider=github-actions` works in cosign 3.1.3 | G2 report | not run |
| L-G2-4 | key-env verify with `--insecure-ignore-tlog=true` works | G2 report | not run |
| L-G2-5 | GitHub keeps the environment variable's exact text (trailing newline) for the hash | G2 report, G11 report | not run |
| L-G3-1 | environment secrets of `pipegen-signing` reach the called sign workflow's job through its job-level `environment:` (no caller `secrets:`) | G3 report | not run |
| L-G3-2 | `cosign login ghcr.io --password-stdin` works in cosign 3.1.3 with the workflow token; cosign sign reads the `DOCKER_CONFIG` folder it wrote; `GITHUB_ACTOR` works as the ghcr user name | G3 report | not run |
| L-G3-3 | `download-artifact` in the called workflow gets the caller run's digest artifact | G3 report | not run |
| L-G3-4 | a private reusable workflow in `pipelines` is callable by the app repo (the Actions access setting) | G3 report | not run |
| L-G4-1 | the DAST run job under Bullfrog with the Docker range reaches the published port through docker-proxy | G4 report | not run |
| L-G4-2 | `docker load` of the BuildKit archive works | G4 report | not run |
| L-G4-3 | image-build under Bullfrog with the Docker range (BuildKit's network) | G4 report | not run |
| L-G4-4 | the key-env sign job works under its egress list (cosign download, ghcr push, artifact download) | G4 report | not run |
| L-G4-5 | the base-scan fetch step on a private repo after a force-push; the base-scan conditions skip as expected with a stored baseline | G4 report | not run |
| L-G4-6 | the Sigstore hosts for the keyless sign job (see the G15a items) | G4 report | not run |
| L-G4b-1 | `node_modules/typescript/bin/tsc` works on a live repo that may run TypeScript 5.x; `--showConfig` on TS 5.x | G4b report, G14 report | not run |
| L-G4b-2 | on ubuntu-24.04 with setup-node's npm, `npm ci` installs only `@typescript/typescript-linux-x64`; `process.platform` and `process.arch` give that name; the shim's `process.execve` works under `env -i` | G4b report, G14 report | not run |
| L-G4b-3 | `--git=/usr/bin/git` works with setup-node's npm, and `/usr/bin/git` exists on ubuntu-24.04 | G4b report | not run |
| L-G4b-4 | the type-check job runs under Bullfrog (the npm registry only) | G4b report | not run |
| L-G5-1 | an unset secret passed under a declared `required: false` name does not stop the run | G5 report | not run |
| L-G5-2 | the verify wait (3 times the job minutes) is long enough; queue time before the gated run starts is not counted | G5 report | not run |
| L-G6-1 | `--prefix=/` on macOS and Windows: a local `node_modules/pipegen` and a project `.npmrc` are not used, and npx still resolves from the registry; on Windows, `/` as a prefix and a hook under Git Bash or cmd | G6 report | not run |
| L-G6-2 | on Windows `/` resolves to `C:\`: check whether a non-admin local user can create `C:\node_modules\pipegen` (if so, use a per-user prefix on Windows) | G6 report | not run |
| L-G6-3 | biome's `--vcs-enabled=true --vcs-client-kind=git` flag names, and what `--staged` does without them | G6 report | not run |
| L-G6-4 | the published pipegen blocks a staged key and passes a clean commit through pre-commit, husky (v9 and v8) and lefthook | G6 report | not run |
| L-G6-5 | the canonical gitleaks hook through real pre-commit: no credit note appears, the hook blocks a staged key, and the audit row says covered | G6 report | not run |
| L-G7-1 | keyless verify works under the egress block | G7 report | not run |
| L-G7-2 | the artifact zip redirect host under Bullfrog: pin the exact results-storage host, never `*.blob.core.windows.net` | G7 report | not run |
| L-G7-3 | the head-check API on a protected branch | G7 report | not run |
| L-G7-4 | the digest artifact's retention path; cosign login to a private ghcr image | G7 report | not run |
| L-G7-5 | the cosign flags `--certificate-github-workflow-*` and `-a` on the pinned cosign version | G7 report | not run |
| L-G7-6 | a self-hosted runner or job container has `curl` and `jq` (the head check fails closed without them); the jq drop through `Accept: application/vnd.github.sha` works | G7 report | not run |
| L-G8-1 | the org `workflows` rule body shape (`do_not_enforce_on_create`, `sha`) | G8 report | not run |
| L-G8-2 | a required workflow calling a private central reusable workflow (the central repo's Actions access) | G8 report | not run |
| L-G8-3 | the gate and find-run inside a required-workflow run (event payload, `workflow_ref`) | G8 report | not run |
| L-G8-4 | classic `checks[{ context, app_id }]` | G8 report | not run |
| L-G8-5 | `sha_pinning_required` on Free private; `GET /user/memberships/orgs/{org}` with a fine-grained token | G8 report | not run |
| L-G8-6 | can a ruleset-required workflow run on `pull_request_review` (`submitted`, `dismissed`)? If yes, add that trigger to `requiredWorkflowForm` and drop the manual re-run note | G8 report | not run |
| L-G9-1 | open the generated `PIPEGEN.md` on GitHub once and look at the table and the fenced command (render check) | G9 report | not run |
| L-G10-1 | `GET /repos/{o}/{r}/rules/branches/{branch}` on a Free private central repo | G10 report | not run |
| L-G10-2 | `POST git/trees` with `content` entries and `base_tree` on a large repo | G10 report | not run |
| L-G10-3 | the environment PUT keeps `wait_timer` and `reviewers` | G10 report | not run |
| L-G10-4 | `compare/{base}...{sha}` for a pin; the `compare` files list (300-file cap) | G10 report | not run |
| L-G10-5 | the setup PR body PATCH works with a fine-grained token | G10 report | not run |
| L-G10-6 | `GET …/commits?path=` and `…/commits/{sha}/pulls` for a squash-merged and a merge-committed record PR; the `created_at` field on `GET …/rulesets/{id}` | G10 report | not run |
| L-G11-1 | GitHub's refusal text for rulesets on a Free private repo (`refusedAsUnavailable`) | G11 report | not run |
| L-G11-2 | `GET …/rulesets?includes_parents=false`; ruleset `created_at` on GET (repo and org) | G11 report | not run |
| L-G11-3 | an org `workflows` rule with `sha` of a commit after the one the file calls | G11 report | not run |
| L-G11-4 | `PUT …/environments/{name}` with `reviewers` ids; environment variable values with a trailing line break kept byte for byte (the verify hash) | G11 report | not run |
| L-G11-5 | `PATCH /repos` `security_and_analysis` on a public repo; `GET …/vulnerability-alerts` 204 and 404 | G11 report | not run |
| L-G11-6 | cosign 3.1.x `generate-key-pair --output-key-prefix` output form (header kind, JSON envelope keys), and that it reads `COSIGN_PASSWORD` without a TTY | G11 report | not run |
| L-G11-7 | `githubFinishProbe` re-reads plan, capabilities and workflow pins on a real repo | G11 report, G13 report | not run |
| L-G11-8 | the org-rule read adds no keys of its own (the exact-keys rule, e.g. no `ref: null`); if it does, `verify` reports false drift | G11 report | not run |
| L-G12-1 | `GET /repos/{o}/{r}/issues?labels=pipegen` and `user.type` for `github-actions[bot]`; `git/blobs/{sha}` serves an old blob that is no longer at HEAD | G12 report | not run |
| L-G13-1 | the run's real stages against real GitHub: the GitHub reads for the build facts, `discover` with `resolvePin`, `trusted`, `prState`, `gateReachable` (the e2e covers them against a fake only) | G13 report | not run |
| L-G13-2 | `generateCosignKeys` on a real `/dev/shm`; the key-env key pair is made in memory and never touches a disk-backed folder | G13 report | not run |
| L-G14-1 | the mid-run confirmation on a real terminal (placeholder run, then real keys) | G14 report | not run |
| L-G14-2 | `ensureActionsAccess` on a real org whose PUT fails with 5xx (the "Left behind" line) | G14 report | not run |
| L-G14-3 | the helper repos are created without wiki or projects (check the repo settings on GitHub) | G14 report | not run |
| L-G14-4 | the cap stop and its resume against real Actions minutes | G14 report | not run |
| L-G15-1 | the runner's image store: `docker info` on GitHub's hosted `ubuntu-24.04` shows whether it is classic or containerd, and a real run passes the digest check on it (a concurrent tag write is the negative control) | G15a report (round 11), progress | not run |
| L-G15-2 | GitHub's own handling of an escaped `\*` in CODEOWNERS (the gate matcher reads it as a literal star, the gitignore reading): one live probe when the release pushes | G15b report | not run |
| L-G15-3 | the `gate/dist` built from the tag `gate-v0.2.3` matches the committed bundle on a clean machine (reproducibility) | G15b report | not run |
| L-prog-1 | the job-level key `cache-mode: none` that `pipegen-verify` and `image-publish` carry (`render-step.ts`, deliberate; the actionlint config ignores it) is a real GitHub key: a delivered workflow with it loads and runs, and GitHub does not answer with a schema error. If GitHub rejects it, every delivered workflow with that key fails to load | progress.md (G15a round 2) | not run |
| L-G17D-1 | a cross-repo `Closes <owner>/pipelines#N` in an app PR body closes the central issue, as GitHub does only when the PR author can write to the central repo; otherwise the issue stays open and the PR still merges | G17D report (row 51), progress.md | not run |
| L-G17B-1 | the compose-path DAST run (pipegen's compose file, a service with a dependency) on a real pull request under Bullfrog: compose up builds the app image inside `dast-run--<svc>` through `registry.npmjs.org` and `ghcr.io` (the hosts its image build reaches), the containers start with `cap_drop: ALL` and `no-new-privileges`, and the scan reaches the app; a start that fails prints pipegen's fixed message under docker's own error. The start from the checked archives (`docker load`, `--no-build`) is a carry. Run it together with the image-build live check: if npm times out (`ETIMEDOUT`) under Bullfrog on the bridge network, the `--no-build` archive start becomes required, not a carry (spike S8) | G17B report | not run |

## G15a live items

From `task-G15a-report.md` ("Live items for G16" and the items added in each round) and `progress.md`. Items 1 to 19 are listed first; items 20 to 26 are the ones the controller named for G16.

| # | Item | Source | Result |
|---|---|---|---|
| G15a-1 | each Sigstore host under Bullfrog's allow-list, and keyless verify end to end under the egress block; is rekor needed for `cosign verify` with the bundled tlog entries? | G15a report | not run |
| G15a-2 | the OIDC token host, and Bullfrog's wildcard support, for the keyless and attest sign jobs (T52 exception) | G15a report | not run |
| G15a-3 | gh 2.103.3 under Bullfrog: `tuf-repo.github.com` and the bundle host; confirm the bundle_url host (`tmaproduction.blob.core.windows.net`) on a private repository's attestation; confirm `--no-public-good` verifies a private repository's attestation end to end | G15a report | not run |
| G15a-4 | gh 2.103.3: the four flags and `--source-digest`, as the pinned binary's help shows them | G15a report | not run |
| G15a-5 | CLOSED live 2026-11-06 (progress.md, "LIVE item closed": the gh v2.103.3 linux_amd64 attestation verified with an independent gh 2.87.3, negative control exits 1; `verifiedWith` and cli/cli in MUST_VERIFY followed in round 3). Re-confirm only if wanted: the gh release's build-provenance attestation, checked with an independent gh; then record `verifiedWith` for the gh entry and add cli/cli to MUST_VERIFY, together, in one change | G15a report | not run |
| G15a-6 | the gh archive holds exactly one file named `gh` at the expected path | G15a report | not run |
| G15a-7 | `docker login ghcr.io` in the digest step, then `actions/attest` with `push-to-registry: true` uses that login | G15a report | not run |
| G15a-8 | attest in a private ghcr repository, end to end (`attestations: write`, `packages: write`) | G15a report | not run |
| G15a-9 | the org required-workflow and default-branch differences for the central sign workflow | G15a report | not run |
| G15a-10 | Scorecard as a `docker://…@sha256` step: whether `with:` reaches the image as `INPUT_*` | G15a report | not run |
| G15a-11 | the same Scorecard run on `schedule` writes `scorecard.sarif` into `/github/workspace` | G15a report | not run |
| G15a-12 | Scorecard under Bullfrog with github-core plus osv: the CII-Best-Practices check's host, and any other host | G15a report | not run |
| G15a-13 | CLOSED live 2026-11-06 (progress.md, G15a round 3: tag v2.103.3 resolves to commit 63837fb778d6a39f02be0ce76ff89f2bc8d74bdc through `gh api`, equal to the attestation's source digest). Re-confirm only if wanted: gh, the attestation's source commit `63837fb778d6…` is the commit of tag v2.103.3 | G15a report | not run |
| G15a-14 | code scanning accepts the scrubbed Scorecard SARIF, including results with no location (the repo-level checks) | G15a report | not run |
| G15a-15 | the weekly `if: github.event.schedule == '23 4 * * 1'` inside the called central nightly workflow (private layout): the caller's event payload is visible there | G15a report | not run |
| G15a-16 | `actions/checkout` (the reviewed pin) with `fetch-depth: 0` on a `schedule` run fetches every branch and tag, so `--all` reaches them | G15a report | not run |
| G15a-17 | code scanning accepts the scrubbed betterleaks SARIF (category `pipegen-secrets-history`), with results that carry `pipegenCommit` and no region | G15a report | not run |
| G15a-18 | the full-history job's runtime and the size of its raw SARIF on a large repository (`--remerge-diff --text` over every ref) against the job timeout and the scrub's raw size cap | G15a report | not run |
| G15a-19 | CLOSED in code (G15a report: the report was captured offline and the fixture is in the tests). The live run is item 24. The ZAP AF active scan report from the pinned zap-stable digest (captured offline; the live run is item 24) | G15a report | not run |
| G15a-20 | the nightly nuclei pair on a `schedule` run: the image build and the archive start in the nightly file, the template fetch under Bullfrog (github-core), and code scanning accepting the scrubbed nuclei SARIF (category `pipegen-dast-nightly--<svc>`, results with URL paths and no repository file) | G15a report | not run |
| G15a-21 | nuclei's `executionSuccessful: false` (always, per the fixture) in a code-scanning upload: does code scanning show the run as failed? | G15a report | not run |
| G15a-22 | on a GitHub runner, `zap.sh -cmd -silent -autorun` as the image user, with `--cap-drop ALL --network host`, against `http://127.0.0.1:<port>`: the time it takes (about 100 s on a 3-URL app here) and the DOM XSS rule's browser under Bullfrog | G15a report | not run |
| G15a-23 | `zap-baseline.py` exit 3 for a target that does not answer: on a runner the merge-layer DAST step fails, and the gate does not read it as clean | G15a report | not run |
| G15a-24 | the ZAP AF active pair on a real `schedule` run: `zap-active-run--<svc>` under Bullfrog (dockerhub, plus the app on 127.0.0.1 over `--network host`); the origin-only context keeps the scan on `http://127.0.0.1:<port>`; the time the AF takes against a real app, inside the 60-minute job; the DOM XSS rule's browser in the container | progress, G15a report | not run |
| G15a-25 | the code-scanning upload of the scrubbed AF SARIF: upload-sarif given a file named `zap-active.json` (not `.sarif`); results whose `artifactLocation.uri` is a URL path, not a repository file; the category `pipegen-zap-active-nightly--<svc>` | progress, G15a report | not run |
| G15a-26 | two nightly DAST pairs per service at once (nuclei and the AF scan): the app started twice in parallel on separate runners, no shared port issue, and the runner minutes of both | progress, G15a report | not run |
| G15a-27 | on a Monday, the weekly cron runs only `scorecard` and `code-scanning`; every other nightly job is skipped (`NIGHTLY_IF`) | G15a report | not run |
| G15a-28 | the Scorecard scrub without `fp-key` on a real run (status ok, the SARIF uploaded) | G15a report | not run |

## Uninstall (V-live)

Plan V's live check, after the Task 8 Step 5 list. Steps only: nobody ran them. Use a private throwaway repo of `CrisWorking` and its own `pipelines`, with a fine-grained token (v0.2 has no App login: you create the helper repos, so uninstall deletes no repo and prints no delete command, with or without `--delete-repos`). Write the **before** lists first (UN-2) and the **after** lists last (UN-8); the difference must be exactly what pipegen made.

| # | Check | Source | Result |
|---|---|---|---|
| UN-1 | create: `pipegen run` on the throwaway repo; the setup PR passes and is merged; `pipegen finish` applies the settings | Plan V V7 | not run |
| UN-2 | the **before** lists, saved to a file: workflows and files pipegen added, secrets (repo, environments, `pipelines`, the scratch repo), variables, environments with their branch rules, rulesets (repo, org rule), classic protection, Actions settings, open PRs, the files of `pipelines` and its CODEOWNERS | Plan V V7 | not run |
| UN-3 | `pipegen uninstall` with no terminal (piped, or `CI=1`) stops before any GitHub call and changes nothing | Plan V V7, V-S13 | not run |
| UN-4 | first run (phase A): the preview names every file, edit and lock; one yes; the PR `pipegen/uninstall` opens; pipegen's own open PRs are closed; the rulesets, the org rule and the classic protection are gone or restored to `previous`; exit 0 with "merge it, then run again" | Plan V V7, V-B2 | not run |
| UN-5 | merge the uninstall PR (the required gate does not block it, because the locks are off); running `pipegen uninstall` before the merge only says to merge | Plan V V7, V-B2 | not run |
| UN-6 | second run (phase B) with `--delete-repos` and a fine-grained token: secrets (`PIPEGEN_` ones directly, an own-name one only after you type it), variables, environments, settings, the scratch repo emptied; the central PR opens; exit 0 | Plan V V7 | not run |
| UN-7 | merge the central PR, run `pipegen uninstall --delete-repos` again: the install record is rebuilt from the saved blob (no "No install record"), no `gh repo delete` command is printed and nothing is deleted; the final message's notes list the scratch repo and `pipelines` as yours to delete by hand (each holds nothing of pipegen's now), the local files go, the final message says there is no App to remove (delete the token); exit 0 | Plan V V7, V6 carry, V8-R1 | not run |
| UN-8 | the **after** lists, compared with UN-2: nothing pipegen didn't create is gone, nothing pipegen created is left except what the final message lists (the kept default branch of the scratch repo, and the two repos you created, until you delete them by hand in UN-11) | Plan V V7 | not run |
| UN-9 | the repos you created: no run prints `gh repo delete` or deletes a repo; `pipelines` is listed as yours to delete only once the central PR merged and no other project is left, the scratch repo only once it is emptied | Plan V V7, V-S3, V8-R1 | not run |
| UN-10 | an object pipegen did not create: a secret or ruleset recreated by hand after the install (same name, new id and `created_at`) is kept and listed "not the one pipegen created" | Plan V V7, V-B6 | not run |
| UN-11 | the throwaway repo, its `pipelines` and `pipegen-proof-<repo>` are deleted by hand at the end | Plan V V7 | not run |

## Release

| # | Check | Source | Result |
|---|---|---|---|
| R1 | after the publish, `npx --yes --prefix=/ --registry=https://registry.npmjs.org pipegen@0.2.0 hook secrets` blocks a staged key and passes a clean commit | progress (2026-11-06), G6 report | not run |
| R2 | the hook files delivered by `pipegen run` name the released version (`pipegen@0.2.0`), not the version of an earlier build | G6 report | not run |
| R3 | npm trusted publishing and provenance for the `pipegen` package work, and the tag ruleset blocks a moved tag (T27) | threat model T27 | not run |
| R4 | the `gate-v0.2.3` tag is pushed at `468dd79af999342fbd525d4dd6fbe57f7e47e375` and `data/reviewed-tools.yml` still pins that commit | pre-flight §5, G15b report | not run |
