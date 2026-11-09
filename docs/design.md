# pipegen: Design

> Status: **v3.2, 2026-10-26.** Design for pipegen. v3.2 applies the security and bug fixes from the third review (see §19, "Hardening rules", which takes priority over earlier sections if anything conflicts).
> Companion document: [`threat-model.md`](threat-model.md) (who could attack and what stops them).
> Working name: **pipegen** (the real name isn't chosen yet).

---

## 1. What pipegen is

A terminal tool that **reads a GitHub project and delivers a complete, proven, protected pipeline for it** as one pull request. When the pipeline needs something the project doesn't have (a Dockerfile, a compose file, tests), pipegen creates it. Everything is **proven on real GitHub runners** before the PR is opened.

**Principle:** people use it because it's good and well done, not because it does half the job. Taking time is fine. The result must be **fully working and compatible with what the user already has**.

**For:** small teams (about 2–15 developers) with nobody dedicated to **security, DevOps or code quality**.

**Why it's different:** a search on 2026-10-26 found no open-source tool that reads a repo and delivers a tailored, *proven* pipeline. StepSecurity hardens existing workflows, Renovate and Dependabot keep pins fresh, GitHub's default code scanning setup is one click but limited, and AI coding agents write workflows nobody can audit. pipegen's edge: **checked by code, proven, and blocking only new problems at first.**

## 2. Milestones: small first, every milestone "fully done" for what it covers

| Milestone | Delivers | Supported projects |
|---|---|---|
| **v0.1 Audit** | `npx pipegen audit`: a read-only report of what you have, what's missing per layer, what pipegen would add, and what it would cost. It needs **no write permissions** and changes nothing. | Any GitHub repo (full detail for Node/TypeScript) |
| **v0.2 Full job: Node/TypeScript** | `npx pipegen`: the complete proven pipeline, the four layers, one PR, plus `uninstall` | Node/TypeScript, **one package** (no monorepo yet) |
| **v0.3** | Keep or Switch for the test framework, the weekly watcher, Slack, **AI code review** on every PR (advisory comments, never blocking; local `pipegen review` or opt-in CI job) | Same |
| **v0.4** | Python, then monorepos | More stacks |

Projects outside a milestone's support get the **audit only**, with a clear message. pipegen never does half a job on them.

## 3. Goals, non-goals, anti-goals

**Goals:** one complete pipeline with **protection at four layers** (pre-commit, push, merge, deploy). Missing pieces are created and proven. It stays compatible with the user's package manager, runtime versions, existing workflows and existing tests. It stays healthy over time.

**Non-goals:** pipegen never deploys (it protects deploys). GitHub only. No dashboard.

**v0.2 scope as built:** `pipegen run` sets up repositories owned by `CrisWorking` only (`SCOPE_LINE`); anything else is refused before any change. This is a release choice for v0.2: it started when the gate repo was private (DECISIONS #83), and it stays although `CrisWorking/pipegen` is public now, so that the first release is tried on one owner's repositories before it widens. Public and private app repos of that owner are both covered.

**One pipeline by default, parts can be skipped:** the full pipeline is the default. `--skip <part,…>` turns off parts the user doesn't want (`tests`, `precommit`, `docker`, `compose`, `deploy`, `locks`, `slack`, `test-migration`). The reason is recorded in `PIPEGEN.md`. **Secrets scanning and the gate can never be skipped.**

**Anti-goals:** half a job; anything unproven presented as done; breaking or replacing what the user has without asking; too many questions; surprise costs.

## 4. What pipegen delivers

1. **Central `pipelines` repo: always private, one per owner** (GitHub only shares private reusable workflows within the same owner, and **only with private repos**). It holds a per-project workflow set. **Public app repos keep their workflows in their own repo** (they can't call a private repo), as a two-level local chain: the caller job `pipegen` in `pipegen.yml` calls the local `./.github/workflows/pipegen-merge.yml`, whose job is `gate`. They use the gate action from pipegen's public repo (`CrisWorking/pipegen` is public, so this works for any public app repo), and the private `pipelines` repo holds only their install record and its `CODEOWNERS` (records only, no workflows). pipegen never makes any repo public and never suggests it.
2. **One pull request** (`pipegen/setup`) with **one commit per part**: caller workflow, pre-commit config, created `Dockerfile`/`.dockerignore`/`docker-compose.pipegen.yml`/tests, `CODEOWNERS` entries, verify-first steps in existing deploy workflows, `.github/dependabot.yml` entry, and `PIPEGEN.md` (plain English: what was set up, why, and what it costs per month).
3. **GitHub settings are applied only after the PR is merged** (`npx pipegen finish`, or automatically if the CLI is still waiting when the merge happens): rulesets/branch protection (with **code-owner review**), the **org required workflow** where the plan allows it, deploy environments, the signing environment + key, the Actions variable `PIPEGEN_BLOCK_FROM`, and the signing public key as an **environment variable** of `pipegen-signing` (§19). **If the PR is closed without merging, no settings are applied**, so a required check can never block a repo forever. If `finish` never runs, the nightly job opens an issue about it.
4. **An install record** in the central repo (`installs/<repo>.json`): every created file (with its blob SHA), every **exact edit** inside an existing file, every secret with its scope (repo, environment, central), every environment with `created: true/false` and its previous settings, ruleset ids and variables. `uninstall` removes or restores exactly this and nothing else.
5. Later milestones: the weekly watcher and Slack (§13).

All changes are **previewed and confirmed** first.

## 5. The four protection layers

Every layer is set up unless the user skips it or the AI shows a reason to skip it (e.g. "nothing is deployed").

| Layer | Where | Guards | Contents (tools chosen per §6) |
|---|---|---|---|
| **1. Pre-commit** | developer machine | secrets never enter git history | secret scan of staged files, format/lint on changed files. It extends the existing hook manager, or adds one. A bypass (`--no-verify`) is caught by layer 2's `hooks-ci` job. |
| **2. Push** | CI, every push | fast feedback | secrets, SAST, dependency scan, unit tests, lint, `hooks-ci` |
| **3. Merge** | CI on PRs + GitHub locks | nothing unchecked reaches `main` | layer 2 + image scan, DAST, full tests, gate. Locks (after merge, §4): required check, required review + **code-owner review** when the repo has ≥ 2 writers, no force-push, CODEOWNERS on pipeline files, and an **org required workflow** (the gate runs from the central repo, so a PR can't change it) on Team/Enterprise orgs |
| **4. Deploy** | build output + deploy paths | only gated artifacts deploy | build once → SBOM → **signing** (see below) → attestation where the plan allows. Existing deploy workflows get a **verify-first** job. Environments are restricted to the default branch. |

**Verify-first checks the workflow, not a check name.** For the commit being deployed, it finds the run of `.github/workflows/pipegen.yml` where:
- `event == push`, `head_repository == this repo`, and the head SHA matches;
- the run's `referenced_workflows` include the central merge workflow at the **expected central SHA**;
- the gate job succeeded.

It **waits** (up to 30 min) when that run is still in progress. It verifies the image signature with the public key stored as an **environment variable of the protected `pipegen-signing` environment** (whose hash is also in the install record), never from a file in the commit. Runs older than the retention period (90 days by default) no longer exist, so verify-first **fails closed** for them: re-run the pipeline on that commit to deploy it.

**Pipeline integrity (a PR can change the workflow that judges it).** On `pull_request`, GitHub runs the workflow files from the PR itself, so a malicious PR could remove scanners and still show a green gate. pipegen layers its defences:
1. The gate **blocks any PR that changes protected paths** unless a CODEOWNER approved it. Protected paths: `.github/workflows/**`, hook configs, `CODEOWNERS`, `docker-compose.pipegen.yml`, and scanner ignore files (`.gitleaksignore`, `.semgrepignore`, `.trivyignore`, …).
2. **New suppressions** a PR adds (`nosemgrep`, `gitleaks:allow`, new ignore entries) are reported as findings that need code-owner approval.
3. **Code-owner review** is required in the ruleset when the repo has ≥ 2 writers.
4. On Team/Enterprise orgs, an **org required workflow** runs the gate from the central repo, which a PR can't edit. This is the only full fix.
5. `npx pipegen verify` (local, read-only) compares the default branch's pipeline files with the install record and reports any drift.

**Remaining risk:** on personal or solo repos, someone who can merge can still weaken the pipeline. pipegen makes it visible (the gate blocks unreviewed changes and `verify` reports drift), but it can't stop the owner. This is documented, not hidden.

**Signing:**
- **Public repos:** keyless signing.
- **Private repos on Enterprise Cloud:** GitHub **artifact attestations** (GitHub's own signing, no public log).
- **Private repos where the signing environment's branch rule is proven** (found by probing and read-back, not by plan name; this includes **Free private** repos, see below): a key-based cosign signature with `--tlog-upload=false`. The key is generated by `finish` and lives in an **environment secret** of a `pipegen-signing` environment that only the default branch can use. Its public key is an environment variable of `pipegen-signing`, and its hash is in the install record.
- **Private repos on Free:** spike S3 found that environments, environment secrets and deployment branch policies work and are enforced there (against GitHub's docs), so pipegen probes for them and signs with the key as above (DECISIONS #86; this replaces the earlier "no signing on Free private"). Key-based signing needs the rule **proven**: `finish` creates `pipegen-signing` with a custom branch policy for the default branch, reads both back, and only then stores a key (the `deploymentBranchPolicies` capability). GitHub may withdraw this without notice; it is verified by the read-back at `finish` and by `verify`.
- **Private repos where that rule can't be proven** (no environments, or the read-back fails): **no signing.** A repo secret could be read from any branch, so the signature would prove little. `PIPEGEN.md` says so. Protection comes from SBOM + gate verification.

**Gate rules:**
- A **new** critical or high finding, or a new leaked secret, **always blocks**, even in warn mode.
- Old problems only warn until the first clean run, or 7 days at most. **2 days before blocking starts**, pipegen opens an issue (and from v0.3 sends a Slack message) listing what's left.
- "New" means: not in the baseline from the last trusted default-branch run. **With no baseline** (first run, expired artifact, fork, or the setup PR itself), the workflow **also scans the base commit** (the PR base, or the push's `before` commit) and compares, so "new" is always a true diff. Findings without a file (image CVEs, DAST URLs) are compared the same way.
- **Counts matter:** if a fingerprint appears more times than in the baseline, the extra ones are new.
- **Trusted baseline only:** the baseline and the clean-run marker are accepted only from `push` runs of `.github/workflows/pipegen.yml` on the default branch of **this** repo (same repository id, not a fork branch that happens to be called `main`), with the run id recorded inside the artifact.
- **Trusted results only:** the gate downloads only the exact artifact names it expects, and checks each SARIF's sha256 against the job output of the job that produced it. Unreviewed tools never run, so nothing else can upload results.
- Secret findings are fingerprinted with an **HMAC of the matched region of the workspace file**, keyed with the repo secret `PIPEGEN_FP_KEY` and computed inside the scanner job before scrubbing (§19), so a **second key in the same file is a new finding**. **Secret text is removed from SARIF before upload** (the secret scan, betterleaks or the gitleaks fallback, runs with `--redact`, and the scrub step rebuilds the SARIF from allowlisted fields). On fork PRs (no key), any secret on an added line counts as new.
- **Secrets in the pull request's history** (Plan C C9 and its fix round 1): the secrets job also scans the pull request's own commits (betterleaks in `git` mode, the whole history checked out), as **one ordered stream** of everything reachable from the head and not from the base: merge commits included (each shown with what its own resolution added, `--remerge-diff`), every file as text. On a `synchronize` after a force-push, the commits the push replaced are in the stream too (they were pushed, so they have leaked). A key added in one commit and removed in a later one is still caught. **Any** finding of that range blocks, with no baseline and no count ("secret added in this PR's history (commit X): rotate it now, even if a later commit removed it"). Coverage is proven by a canary commit that is the stream's last: the scanner finds it only when it read the stream to its end, and a scan without it blocks. On a push to the default branch the range is informational, and an event with no range (the push that made the branch, `workflow_dispatch`, `schedule`) skips it with a note; on a pull request a missing range blocks. Known costs, all false blocks (fail closed): a merge from the default branch into the pull request brings that branch's newer commits into the range, so a secret there blocks the pull request too. Not covered: a commit replaced two or more pushes ago (rotate a secret when it is first reported), commit messages, and, for private repositories, the replaced commits when the job can't fetch them (the scan then blocks).
- Not-proven parts are judged by their **job result** (no `continue-on-error`), and the gate treats them as warn-only because they are in its `not-proven` input (they're never in the required list).

**Nightly scans (v0.2):** the nightly file also runs, for each web app the merge layer starts for DAST, a nuclei scan with pinned templates and a **ZAP Automation Framework active scan** from the pinned `zap-stable` image (one pair per app: a run job that has **no key and no secret** and a scrub job that removes anything that looks like a secret, then one upload job that sends the scrubbed results to code scanning, categories `pipegen-dast-nightly--<service>` and `pipegen-zap-active-nightly--<service>`). The active scan runs against the app started in the run job at `127.0.0.1`, its plan has a hard time limit (about 45 minutes at most, a 60-minute job guard), and it is **reported, never gating**: the gate reads only the pull-request results. Where code scanning is not available the nightly DAST is not run and `PIPEGEN.md` says so. The estimate counts it at about 5 minutes a night and shows the 45-minute ceiling.

The same nightly file also runs, all reported and never gating: a **secrets scan of the whole history** (betterleaks over every ref, merge commits shown with `--remerge-diff`, uploaded to code scanning under `pipegen-secrets-history`), **zizmor's online audits** of the workflows (the job's own read token as `GH_TOKEN`, sent to `github.com` only), and **Scorecard** (weekly, on Mondays; the other nightly jobs skip that day). Two limits of the history scan are permanent and fail closed: a merge with three or more parents anywhere in the history makes the job fail every night, and so does a commit dated after 2100-01-01. Without code scanning (a private user repo, or an organisation without Code Security) the history scan and the nightly DAST are not written, and `PIPEGEN.md` says so.

**Paid-plan limits:** detected up front by **probing the endpoints** (the plan name isn't always readable). On Free private repos, pipegen sets up everything else and says clearly what's missing, suggesting **GitHub Pro (personal accounts) or GitHub Team (organisations)**. Code scanning upload is used only where it's enabled (it needs the paid Code Security add-on on private repos), and the gate never depends on it. It **never suggests making a repo public**. Merged-while-red alerts cover the gap (v0.3).

## 6. Choosing tools: a reviewed list for blocking, live suggestions for the rest

- **Blocking tools come only from the reviewed list** (`data/reviewed-tools.yml` in pipegen's repo). Each entry is a specific tool + version + pin + step template that a pipegen maintainer reviewed. (v0.1: human review + exact pin. From v0.2: also at least one passed proof run.) **Platform actions (checkout, upload-artifact, cache…) and container images** (base images, ZAP, the local registry) are in the list too, with stored SHAs/digests and the same moved-tag check. The list grows over time, and bumps of the gate, the watcher or list entries wait a **7-day cooldown** before release.
- **Live discovery** (the AI + GitHub/npm search) still runs, but what it finds that isn't on the reviewed list is **only mentioned** in `PIPEGEN.md` as a suggestion. It is **never run** in the user's CI (an unreviewed tool running on private code could copy it out). It can join the reviewed list only through a reviewed PR to pipegen.
- **Every candidate is verified live:** the repo exists, the quality bar is met (maintained, used, Scorecard, licence, no advisories), it's pinned exactly, and it's **not a near-duplicate name** of a reviewed tool from a different owner (typosquatting).
- **A moved tag is an alert, never an update.** If a reviewed tool's tag now points to a different commit than the reviewed pin, pipegen **keeps using the reviewed SHA**, never adopts the new one, and raises a loud alert (this is exactly the tj-actions attack: SHA-pinned users stayed safe). Commits that only exist in a fork ("impostor commits") are rejected.
- The AI never writes YAML. It fills `StepSpec`s, pipegen renders them, and the referee (plain code + actionlint + zizmor) has the final say.

## 7. Audit mode (v0.1)

`npx pipegen audit`:
- **Read-only.** It needs only read access to the one repo. It creates and changes nothing, and **no AI is needed** (optional `--ai` suggestions require consent).
- The report has:
  1. the current pipeline mapped to the four layers (which tools already cover which needs);
  2. the gaps, by severity;
  3. what pipegen would add (reviewed tools);
  4. what it would create (Dockerfile, tests…);
  5. what the GitHub plan allows;
  6. **estimates**: setup Actions minutes, **monthly** Actions minutes afterwards (from the repo's last 30 days of pushes and PRs), approximate AI cost, and approximate time;
  7. the permissions the full run would need.
- Output in the terminal, plus an optional local `pipegen-audit.md` (never committed by pipegen).
- **Project type and the minimum (Plan J).** pipegen reads each service's type from local facts (`static-site`, `library`, `cli`, `server`, `container`; a doubtful one is marked unsure and treated as a server) and shows it with its evidence. The type only removes checks that cannot apply (no image or running-app scan for a static site); the minimum (secrets, dependencies, code scan, workflow lint, action pinning, merge gate) is kept for every type. A row is credited as covered only when the repo has the equivalent (for example a pull-request run standing in for every push, or hooks that CI re-runs), and the report says so. The default terminal report is short (at most 32 lines); `--verbose`, Markdown and JSON keep everything. `test/plan-j-proof.test.ts` checks all of this on invented repos of each kind against rows recorded before Plan J.
- With `--ai`, nothing leaves the machine until a required local secret scan (betterleaks; gitleaks as the fallback, with `PIPEGEN_SECRET_SCANNER` set to `gitleaks`) has run over the code to send. Both are pinned, checksum-verified binaries, and the consent screen names the one that runs.

## 8. The full flow (v0.2) and the only questions

```
support check → consent (incl. estimates) → read → needs → tools (reviewed + suggestions)
→ debate → create missing pieces → secrets → assemble → referee + guard
→ PROOF in private per-project scratch repo (fix loop) → preview → PR
→ (after merge) settings → done
```

Questions: (1) consent; (2) values pipegen can't detect, e.g. a Stripe **test** key ("use test keys only; they're deleted from the test repo after the proof"); (3) the Slack webhook (v0.3); (4) Keep or Switch (v0.3); (5) final confirmation.

**Shown at consent:** the files that will be read and the provider; the private repos to create; **setup Actions minutes (hard limit 2×)**; **estimated monthly minutes afterwards**; **approximate AI cost** (or "free, local" for Ollama); approximate time; the permissions used.

## 9. Creating what's missing

**pipegen never edits the application's own source code.** It only adds files and edits build/test config and test files.

| Missing | Created | Proven by |
|---|---|---|
| Dockerfile | multi-stage, non-root, base image pinned by digest, `.dockerignore` (always excludes `.env*`) | builds, starts, answers HTTP with a status < 500 |
| Services (DB, cache…) | `docker-compose.pipegen.yml`, passwords generated at runtime | the app starts against them |
| Tests | starter tests for public behaviour | all pass. `PIPEGEN.md` notes they **describe current behaviour** (they can lock in today's bugs) |
| Hooks | config for the stack | run clean in CI |

**New packages** the AI adds (e.g. test devDependencies) must **exist in the registry and pass the quality bar**. That stops made-up package names.

**AI changes that run code are shown separately.** Any change to `package.json` scripts or dependencies gets its own section in the preview and needs its own confirmation. Installs use `--ignore-scripts` where possible. Created tests and Dockerfiles run with no secrets beyond the proven runtime environment. A fix-loop answer may only touch the files of the part that failed. Logs are given to the AI only as code-extracted excerpts marked untrusted (§19).

**Symlinks are never followed.** Reading uses `lstat`, writing refuses symlinks, and every resolved path must stay inside the project, so a symlink to `~/.aws/credentials` can't be read or sent anywhere.

**When a part can't be proven:** ask for what's missing. If it still can't be proven, deliver everything else, mark that part **"not proven"** (warn-only), and keep asking: an open issue, a nightly check whether the secret now exists, a reminder on every run. When it's proven, a PR turns it into a blocking check.

**Keys are always GitHub secrets, never in code.** Values never appear in files, logs, PRs, issues, AI requests or Slack.

## 10. Builder vs judge

The builder ("developer") picks among **reviewed tools** for blocking needs, and lists suggestions (mention-only). The judge ("security engineer") attacks. At most 3 rounds. Remaining disagreements are decided automatically by **proof runs against planted problems** + scoring (+20 per planted critical caught, +10 per other, −1 per minute; missing a critical or timing out loses; a near tie goes to the judge's option). No vote. The judge also decides whether deploys need an approval.

## 11. Proof

- **One private scratch repo per project:** `pipegen-proof-<repo>`.
- **Only the current files (HEAD) are copied, no git history**, so old secrets in the history aren't copied.
- **The user's own workflow files are never pushed** to the scratch repo (a push would trigger them before they could be disabled). Only pipegen's workflows, the proof harness and **compat copies** (hardened copies of the user's build/test jobs, deploy jobs removed; see §19) are pushed. As a second safety net, any other workflow found there is disabled. **Secrets are stored only after that**, and outbound network access in proof jobs is limited with a reviewed egress-control tool.
- Proof covers: build, the app starts (status < 500), every blocking scanner reports, tests pass, hooks run, sign-and-verify against a local registry (**always key-based with no public log in the scratch repo**), the verify-first run lookup, the gate decision, and **the user's existing build/test jobs still pass** (compat copies, compared with their last result on the user's default branch).
- **Fix loop:** 5 attempts per failing part, then the next reviewed tool, then not-proven or stop with an explanation.
- **After the proof:** proof branches, **workflow runs, artifacts and caches** are deleted, **secrets stored in the scratch repo are deleted**, and the scratch repo is **deleted** when the token allows (otherwise emptied, see §19). The user can delete it with `uninstall --delete-repos`.
- **Hard minutes cap:** 2× the estimate shown at consent (one estimator). Usage is computed from the jobs API (each job rounded up to a whole minute).

## 12. Access, AI and privacy

- **Least-privilege access** (spikes S1 and S9 done, DECISIONS #87, #88): pipegen's own **GitHub App** first, logged in with the device flow and installed on "Only select repositories" (an installation on "All repositories" is refused unless `--allow-broad-token`). With the App, **pipegen creates the private helper repos itself** (`pipelines`, `pipegen-proof-<repo>`; they join the installation at once) and deletes the scratch repo after the proof. **Fallback: a fine-grained token** limited to exactly the app repo, `pipelines` and `pipegen-proof-<repo>`; only in this mode does the user create the helper repos (pipegen prints the exact `gh repo create … --private` commands), and pipegen never creates or deletes repos (it empties the scratch repo instead). Permissions are checked by **probing**, not by reading classic scopes or `GET /repos` `permissions`. **Classic broad tokens are refused** unless `--allow-broad-token` (with a warning). An Actions `GITHUB_TOKEN` is accepted for the read-only audit only. The exact permissions are listed in the README and at consent.
- **AI is needed for the full job** (Claude by default, model `claude-opus-5-5`, configurable; OpenAI and Ollama are experimental). It's **not** needed for the audit.
- Code sent to the AI excludes secret files and is redacted (tokens, keys, passwords, **connection strings**).
- **Prompt injection:** text inside the repo can't make anything blocking (blocking = the reviewed list only). AI output is checked by code before use, and unreviewed tools are only mentioned, never run.

## 13. Watcher and Slack (v0.3)

- **Weekly** (central): advisories, archived or degraded tools, **moved tags** (urgent), Scorecard drops → a PR to a newer reviewed version, or an issue. **Nightly** (app): drift → issue "re-run pipegen". Missing keys → issue + reminder. Warn-mode ending → issue 2 days before.
- **Slack:** blocked, critical, merged while red, warn mode ending, missing key (weekly at most), watcher news, proof result. The webhook is a secret, and sending never fails a pipeline.

## 14. Uninstall (v0.2)

`npx pipegen uninstall`:
- previews, then opens a PR removing everything pipegen added (it asks whether to keep the created Dockerfile/tests, which the team may want);
- removes the rulesets, environments and secrets pipegen created (from the install record);
- removes the project from the central repo (via PR);
- empties the scratch repo.

`--delete-repos` deletes the scratch repo, and the central repo if no project is left. That needs extra repo-deletion rights (Administration: write), asked for only then.

Only what pipegen **created** is deleted. Environments that existed before pipegen get their **previous settings restored**, not deleted. Only secrets with the `PIPEGEN_` prefix that the record says pipegen created are removed.

## 15. pipegen's own supply chain

pipegen's repo is **public** (other pipelines use its gate). Its releases are hardened before v0.1:
- npm **trusted publishing** (provenance is automatic for public packages; it needs npm ≥ 11.5.1 and Node ≥ 22.14 on a GitHub-hosted runner), signed tags, and a **tag ruleset** so only maintainers can create `v*` tags;
- users are told to run an **exact version** (`npx pipegen@x.y.z`) and can check it with `npm audit signatures`;
- rulesets on its own repo, `CODEOWNERS`, `SECURITY.md`;
- OpenSSF Scorecard with a target of **9+**;
- Dependabot, actionlint + zizmor on its own workflows;
- a goal of a **second maintainer**.

The reviewed list and the published gate are high-value targets: changes to them need review by a CODEOWNER.

## 16. Technology

TypeScript, run with `npx pipegen`. Reused: actionlint, zizmor (referee), cosign.

## 17. Parked

false-alarm button · NIS2 / ISO 27001 view · README badge · GitLab and others · Teams/Discord · full baseline (block only new findings, forever).

## 18. Open

Name (working name: pipegen). Licence: **Apache-2.0** (chosen 2026-10-26).

## 19. Hardening rules (v3.2: fixes from the third review)

These rules take priority over anything earlier in this document.

**Merge lock and approvals**
- The required check is **bound to the GitHub Actions app** (`integration_id`), so a commit status posted through the API can't satisfy it.
- Rulesets set `dismiss_stale_reviews_on_push` and `require_last_push_approval`. The gate counts an approval **only if it was given on the current head commit**. Approving re-runs the merge layer (`pull_request_review` trigger).
- CODEOWNERS for pipegen's paths lists **user logins** (the default `GITHUB_TOKEN` can't resolve team membership). If there's only one code owner, the ruleset allows the **admin role to bypass through a PR**, so the owner isn't locked out.
- `finish` also protects the **central repo** with a ruleset and CODEOWNERS covering `.github/workflows/**` and `installs/**`. A hash of the install record is kept locally and in the setup PR body, and `verify` compares them.
- When the plan allows it, `finish` turns on **`sha_pinning_required`** for Actions.
- `finish --print` outputs the exact `gh api` commands instead of running them, so a security team can review and run them itself.
- `finish --rotate-key` rotates the signing key.

**Pipeline integrity**
- **Fail closed** when the PR's file list is incomplete (3,000 or more files) or a text file has no patch.
- Renames are checked by their **old path too**.
- Protected paths are the base list **plus every config and ignore file declared by the reviewed tools in use** (e.g. `.gitleaks.toml`, `osv-scanner.toml`, `trivy.yaml`, `.trivyignore.yaml`), plus `.github/actions/**`, `docs/CODEOWNERS` and `.github/dependabot.yml`.
- Suppression markers include `nosem`.
- Scanners and linters run with **explicit, pinned configs** from the reviewed templates, so config files inside the repo are never picked up silently.
- **Installing exemption:** when the base branch has **no pipegen install** yet, integrity findings are warnings ("installing pipegen: review these files"). This is decided by the install state of the base branch, **never by the branch name**.
- `not-proven` can never include floor needs (secrets, sast, deps, tests, gate). The gate has this rule built in. For private repos, the list lives in the central per-project workflow, not in the app repo.

**Trusting results**
- `pipegen.yml` triggers on `push` to the **default branch only** (`push: branches: [<default>]`, never tags: a tag named like the branch would look trusted) and on `pull_request`, with `concurrency` per ref that cancels in-progress runs **except on the default branch** (baseline, signing and deploy runs always finish). No gate job runs on a push to another branch (it has no pull request, so no integrity check; the gate action refuses to pass there too). The push layer on feature branches is a separate file, `pipegen-push.yml`, which triggers on `push` with `branches-ignore: [<default>]` and no tag filter (so a tag never runs it either); it runs scanners only, and skips when the branch has an open PR, because the merge layer covers it.
- A **trusted run** also requires its `head_sha` to be in the default branch's history.
- Every job that feeds the gate, builds, signs or verifies runs with **`cache-mode: none`**, and scanners' own caches are off (e.g. Trivy runs with pipegen's pinned config, `cache.backend: memory`).
- `base-scan` runs **every blocking scanner that can run on the base commit**. Dependency and image findings are **always** compared with the base scan from the **same run** (a CVE published yesterday in an unchanged dependency is not "new"). Findings from scanners that can't run on the base (e.g. no Dockerfile yet) are warnings on installing PRs, and otherwise block.
- **Secret fingerprints** are an HMAC of the matched secret using the repo secret `PIPEGEN_FP_KEY`. They're computed inside the scanner job before scrubbing. On fork PRs (no secrets), any secret on an added line counts as new.
- On fork PRs, jobs that need secrets report **"not run"**, not "failed".
- A tool error (a scanner crash, or a database download that fails after a retry) is reported separately from a finding.

**Deploy**
- Verify-first takes the SHA **from what is deployed**: `github.sha` for push deploys, `workflow_run.head_sha` for `workflow_run` deploys.
- Deploy workflows with other triggers (manual dispatch with a `ref` input, `pull_request_target`, …) **don't get the verify job**. `PIPEGEN.md` lists them as an unprotected gap.
- Verify-first also checks `head_branch` and outputs the verified image digest. A signature only protects deploys that use that digest.
- Verify-first runs inside the `pipegen-signing` environment (to read the public key), so it only passes for deploys from the **default branch**. Deploys from other branches are listed as a gap.
- `PIPEGEN_BLOCK_FROM` can be changed by anyone with write access, so its value is also recorded and `verify` reports drift. Changing it only affects old findings: new critical and high findings always block.

**No workflow edits from CI**
- The default `GITHUB_TOKEN` can never change workflow files. So the watcher and the nightly job **open issues that contain the exact patch**, and `npx pipegen update` (run by the user with their token) applies them.
- Dependabot keeps bumping the central SHA in app repos, with a **7-day cooldown** (`cooldown`) in the generated `dependabot.yml`.

**Proof and scratch repo**
- The scratch repo's default branch gets the **base snapshot** (the user's current files, without their workflows).
- The proof opens a **PR** from the proof branch, which runs the merge layer exactly as it will in the user's repo, including base-scan and the installing exemption. It then **merges** that PR, which runs the deploy layer, and `verify-lookup` checks the resulting run. Workflows are started by **push and pull_request**, never `workflow_dispatch` (that needs the file on the default branch).
- **Compat copies** run on GitHub-hosted runners only, with `permissions: contents: read`, and with `id-token`, `environment` and `secrets.*` removed. Jobs that need more are reported as "not compared".
- **AI-changed code first runs with placeholder secrets.** The real test keys are used only after the user confirms those changes in a short mid-run confirmation (a "confirm before it runs with your keys" screen).
- Scratch secrets are deleted **right after the proof**, before the preview.
- Before creating the scratch repo, the org's base permission is checked, with a warning if members could read it. When the token allows, the scratch repo is **deleted after the proof**. Otherwise it's emptied, and the user is told how to delete it.
- **Install records live in the private `pipelines` repo for every project.** Public app repos get a records-only private `pipelines` repo.

**AI**
- The default model is `claude-opus-5-5` (the user can choose another).
- JSON comes through **structured outputs** (`output_config.format`). There's no forced `tool_choice` and no `temperature`.
- Ids (needs, candidates, files) are **enums** in the schema.
- `stop_reason` is checked for `refusal` (using the server-side refusal fallback, which the user is told about) and for `max_tokens`.
- The code bundle is prompt-cached.
- **Hard AI cost cap** of 2× the estimate. The estimate splits input and output tokens.
- **Redaction** also excludes:
  - files: `*.tfstate`, `*.tfvars`, `.npmrc`, `.netrc`, `*.p12/.pfx/.jks`, kubeconfig;
  - token types: JWTs, Slack webhook URLs, `AIza…`, `npm_…`.

  A secret scan (betterleaks; gitleaks as the fallback) runs over everything sent, and every value the user typed is removed by exact match, including its base64 and URL-encoded forms.
- Logs go to the AI only as a **code-extracted error excerpt** inside a block marked as untrusted.
- AI text placed in `PIPEGEN.md` is cleaned (no links, HTML or @mentions, and a length cap).
- Security-relevant step inputs are **fixed by the reviewed templates**, and the AI only chooses from enums.
- **Planted problems run in every proof**, so each blocking scanner must catch its planted item.
- `requireDeployApproval` is a **rule** (deploys exist and ≥ 2 writers). The AI can only turn it on.
- **Fix loop:**
  - failures are classified by rules first (a missing secret, a runner error or a rate limit doesn't call the AI);
  - earlier attempts are sent along;
  - it stops when the same error repeats twice;
  - there's a global attempt cap per run.
- **Created tests:** the count can't drop between attempts, no `.skip`/`.only`, and they run twice to catch flaky tests.
- **Ollama is experimental** (`num_ctx` set explicitly).

