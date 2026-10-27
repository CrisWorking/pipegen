# Releasing pipegen

Status: **nothing has been published and no release tag exists** (DECISIONS #83: the public release, the npm publish and
the signed tags happen only when v0.4 is done). This page has two parts: what is already built and how it is guarded
(R-build), and the checklist for the one release session (R-publish).

**Rules that apply to every step below**

- **Ask Cristiano first.** Every R-publish step touches GitHub, npm or the public. None of them is run on Claude's own
  initiative, and each one starts with "ask Cristiano, and check that the public repo exists on GitHub".
- **Cristiano does all posting** (DECISIONS #85): Show HN, LinkedIn, announcements, replies. Claude never posts or announces
  anything. Claude may write a draft in `pipegen-internal` if asked.
- **Never push a `v*` tag before v0.4.** Milestone marks use another naming (for example `internal/v0.1`) or none.

## What is built (R-build)

| Piece | File | Guard |
|---|---|---|
| Release workflow | `.github/workflows/release.yml` | Runs only on pushed `v*` tags **and** only when `github.event.repository.visibility == 'public'` **and** the repository is `CrisWorking/pipegen`. In the private repo a `v*` tag starts nothing. |
| Release check | `scripts/release-check.ts` | Run by `release.yml` (and by hand, below). Not part of pull-request CI: it is expected to fail until the owner has reviewed the lists. |
| Scorecard | `.github/workflows/scorecard.yml` | Runs only when the repo is public. |
| Cooldown | `scripts/cooldown.ts` | Pull requests; see [cooldown.md](cooldown.md). |

How `release.yml` works, in order:

1. **verify**: the tag must be `vMAJOR.MINOR.PATCH`, annotated and signed by a key in `.github/release-signers` (`git verify-tag`; the tag must point at the run's commit), and point at a commit on `main`; that commit must have a green `ci` run
   (the live-network gitleaks test is not re-run, S13); exact Node 26.12.0 and npm >= 11.5.1 are asserted (S10); then
   `npm ci --ignore-scripts`, tests, `tsc --noEmit`, build, the release check, **one** `npm pack`, a CycloneDX SBOM of the bundled
   packages (the same list as `THIRD_PARTY_NOTICES`; `node scripts/notices.ts --sbom-only`), a test of the packed `.tgz`, and `SHA256SUMS`. What is tested is what ships (S1).
2. **attest**: a build provenance attestation (`actions/attest-build-provenance`) for the `.tgz` and the SBOM.
3. **publish**: environment `npm-release`; `npm publish ./pipegen-X.Y.Z.tgz --provenance` (pre-releases use `--tag next`), with **trusted publishing only**
   (an OIDC token; no npm token is stored anywhere, and the job refuses to run if one is set). `id-token: write` exists
   only in the attest and publish jobs.
4. **github-release**: creates a **draft** release, uploads the `.tgz`, SBOM and `SHA256SUMS`, then publishes it. Immutable
   releases lock assets at publish, so nothing can be added later; a failed immutable release burns the tag (S2).

Every job has minimal permissions (`permissions: {}` at the top), and every action is pinned to a commit SHA.

### The release check (S18)

```bash
npm run build
node scripts/release-check.ts --tag vX.Y.Z   # from the repo root
```

It fails (exit 1) unless all of these hold:

1. no `PENDING` `reviewedBy`/`reviewedAt` in `data/reviewed-tools.yml` and `data/pinned-binaries.yml`;
2. `package.json` has no `dependencies` (everything shipped is bundled);
3. `THIRD_PARTY_NOTICES` equals what the current build generates;
4. the version in `package.json` equals the tag;
5. the 7-day cooldown passes for everything changed since the previous `v*` tag (everything, on the first release);
6. `checkedAt` in `data/ai-prices.yml` and `data/github-plans.yml` is at most 30 days old.

**Owner dependency:** the release is blocked until Cristiano has reviewed every `PENDING` entry (today: 23 in
`reviewed-tools.yml`, 3 in `pinned-binaries.yml`) and set `reviewedBy` and `reviewedAt` in a pull request. Claude never
fills these in.

## R-publish checklist (v0.4, one session, Cristiano present)

Work through it in order. Tick a step only after Cristiano said go and the result is recorded here.

### A. Before the repository goes public

- [ ] **A1. Review the `PENDING` lists** (ask Cristiano first; it is his review). Every entry in `data/reviewed-tools.yml` and
      `data/pinned-binaries.yml`: repo, version, pin, `fixedInputs`, `choices`, `configFiles`. Then `reviewedBy` and
      `reviewedAt` in a PR.
- [ ] **A2. Refresh the data that freezes outside facts** (ask Cristiano first). Each refresh cites its source in the file:
      AI prices (`data/ai-prices.yml`, from the providers' pricing pages) and `data/github-plans.yml` (GitHub's plans page),
      both with a new `checkedAt`; the pypa/gh-action-pypi-publish release-commit SHA list (it stops at v1.14.3); the
      pre-commit hook upstream URLs.
- [ ] **A3. SECURITY.md** (ask Cristiano first; S9). Replace the placeholder contact line and confirm or change the response
      times (draft: acknowledge in 7 days, fix or advisory plan in 30, supported = latest minor). His personal email goes in
      only with his say-so.
- [ ] **A4. README maintenance promise** (ask Cristiano first; S9, DEC #99). The README holds a draft; he approves or edits it.
      These are public promises he has to be able to keep.

### B. Making the repository public, and GitHub settings

- [ ] **B1. Make the repo public** (ask Cristiano first; irreversible in effect). Check that `CrisWorking/pipegen` exists as
      public before any step below. Rulesets, immutable releases and Scorecard need a public repo on GitHub Free (a 403
      proves it).
- [ ] **B2. Throwaway proofs in `pipegen-spike-release`** (ask Cristiano first; creating this repo is itself a public act, as
      rulesets need a public one; S4). Copy `release.yml` and change its repository-name guard to the spike repo (as copied, every job is skipped), and
      stub out the publish step and the release check (which fails on `PENDING` entries there). Create the `npm-release` environment (deployment rule: `v*` tags
      only), the tag ruleset, and turn on immutable releases. Prove **only the GitHub side**:
      - a run from a branch cannot enter `npm-release`;
      - an unsigned `v*` tag: record whether the tag ruleset refuses it, or that GitHub offers no signature rule for tags
        (then the maintainer checks with `git tag -v` before every release);
      - editing or deleting the assets of a test release fails (immutable);
      - `id-token: write` appears only in the attest and publish jobs;
      - `npm publish --dry-run` works (it never contacts the trusted publisher, so it proves nothing about npm).
      Do **not** publish a throwaway package to npm. Record the results here. The npm side is verified once, at the first
      real publish (step C3).
- [ ] **B3. Delete `pipegen-spike-release`** (ask Cristiano first; destructive). `gh auth refresh -s delete_repo` first, then
      `gh auth refresh -r delete_repo` to drop the scope again.
- [ ] **B4. Tag ruleset and immutable releases on the real repo** (ask Cristiano first). Only maintainers can create, move or
      delete `v*` tags; require signatures if GitHub offers that rule for tags. Turn on **immutable releases**. Record the
      ruleset id and the setting here.
- [ ] **B5. `npm-release` environment on the real repo** (ask Cristiano first): deployment branches and tags limited to `v*`
      tags. When a second maintainer exists, also turn on required reviewers and "prevent self-review" for it.
- [ ] **B6. Rulesets on `main`, just before the first release, not during the build** (ask Cristiano first): pull requests
      required, required checks of `ci` (including `cooldown`), no force-push, no deletion, signed commits required, and
      code-owner review of `/.github/`, `/scripts/` and `/data/` (this is what makes the cooldown and the trust-root lists
      more than advisory, see [cooldown.md](cooldown.md)). A solo owner cannot approve their own PRs, so the owner needs a
      bypass on the PR rules (DEC #74). Record the ruleset ids here.
- [ ] **B7. GitHub private vulnerability reporting on** (ask Cristiano first; S9).
- [ ] **B8. The `security-fix` label** (ask Cristiano first). Nothing uses it today: the cooldown has no emergency path (S5 was not built; see [cooldown.md](cooldown.md)). Create the label only if step D1 decides to build that path.
- [ ] **B9. Scorecard** (ask Cristiano first; S11). Run `scorecard.yml` once (`workflow_dispatch`); results are published to
      the OpenSSF API. Record the score here. Show Cristiano a **list** of every check under 9 (name, score, meaning,
      suggested fix). Checks that need a second maintainer (Code-Review, Contributors, part of Branch-Protection) are marked
      "needs second maintainer", not as fixes. Fuzzing and CII-Best-Practices are expected to be low. Open no issue without
      asking him again. "9+" is the aspiration of design section 15, not a promise.

### C. The first release

- [ ] **C1. Signing key** (ask Cristiano first). Once: GPG, or SSH with `git config gpg.format ssh` and
      `git config user.signingkey <key>`; add it to GitHub as a **signing key**.
- [ ] **C1b. Pin the tag signer** (ask Cristiano first). Cristiano adds his tag-signing public key to
      `.github/release-signers` (ssh allowed_signers format, `namespaces="git"`) in a PR. The file ships with only a comment,
      so `release.yml` fails closed on every tag until he does. The `verify` job runs `git verify-tag` against this file.
      Together with the B4 ruleset (it must block **updates and deletions** of `v*` tags, so a verified tag cannot be moved),
      this makes "built from a signed tag" true.
- [ ] **C2. Check before tagging** (ask Cristiano first): on a clean checkout of `main` at the release commit, `npm ci`,
      `npm test`, `npx tsc --noEmit`, `npm run build`, `node scripts/release-check.ts --tag vX.Y.Z` (it must be clean), and
      `package.json` `version` = X.Y.Z with `repository.url` exactly `git+https://github.com/CrisWorking/pipegen.git`.
- [ ] **C3. Reserve the npm name, then add the trusted publisher** (ask Cristiano first; **whether to reserve the name at
      all is still his open decision**, and the claim is public and irreversible, S4). A trusted publisher can only be added
      to a package that exists, so if he decides to reserve: publish a placeholder pre-release by hand with 2FA, under a
      non-`latest` dist-tag, from a scratch folder that holds only a minimal `package.json` (not the real tarball):
      ```bash
      npm publish --registry=https://registry.npmjs.org --access public --tag reserve    # version 0.0.0-reserve.0
      npm deprecate --registry=https://registry.npmjs.org "pipegen@0.0.0-reserve.0" "name reservation only, not a release"
      ```
      The real version is **never** published by hand: only the tag run (C4) publishes it, with provenance. Then, on
      npmjs.com in the package settings (an npm-account action by Cristiano): add the trusted publisher bound to
      repository `CrisWorking/pipegen`, workflow `release.yml` **and** environment `npm-release`. Record it here.
- [ ] **C4. Signed tag and the release run** (ask Cristiano first). The run publishes the real version X.Y.Z (a pre-release
      tag such as `v1.0.0-rc.1` goes under the `next` dist-tag, never `latest`). The `verify` job fails unless the tag is
      annotated and signed by a key listed in `.github/release-signers` (C1b). `git tag -s vX.Y.Z -m "vX.Y.Z"`, check with
      `git tag -v vX.Y.Z`, then `git push origin vX.Y.Z` (this is the public step and starts `release.yml`). Watch the
      run; approve the `npm-release` environment when asked.
- [ ] **C5. Verify the provenance** (ask Cristiano first; S17, DEC #99). No earlier than this publish:
      ```bash
      mkdir /tmp/verify && cd /tmp/verify && npm init -y >/dev/null
      npm install --registry=https://registry.npmjs.org pipegen@X.Y.Z
      npm audit signatures          # registry signatures and provenance attestations verify
      ```
      Check that the package page on npmjs.com shows the provenance link and that it points at the `release.yml` run for the
      tag. Also `gh attestation verify <the .tgz from the release> --repo CrisWorking/pipegen`. Record the result here.
- [ ] **C6. "Disallow tokens"** (ask Cristiano first). Once trusted publishing has worked: set the npm package's publishing
      access to "require two-factor authentication and disallow tokens", and revoke any token used for the manual first
      publish. Record both here.
- [ ] **C7. Direct or staged publishing** (ask Cristiano first): decide whether `release.yml` publishes directly (as built) or
      through a staged publish that needs a human approval on npm.
- [ ] **C8. Announcements** are Cristiano's alone (DEC #85). Nothing is posted by Claude.

### D. Decisions left open

- [ ] **D1. Decide the emergency path for urgent security fixes** (ask Cristiano first). The cooldown has none today (S5 was
      not built). Decide whether to build one (for example the `security-fix` label plus a `Security-fix-reason:` line,
      with owner review) and what the README and the PR template then say.

## Notes

- **Pins in this workflow** (Node, actions) follow the 7-day cooldown like every other pin. Bump them in a PR; the
  `cooldown` job does not read workflow files, so check the release dates by hand.
- **When a second maintainer exists:** enable "required reviewers" and "prevent self-review" on `npm-release`, require two
  approvals for emergency-path PRs, if D1 builds one.
- **Recorded results** (filled in during R-publish): tag ruleset id: none yet. Main ruleset id: none yet. Immutable releases:
  not on yet. Scorecard score: not run yet. Trusted publisher: not configured yet. Disallow tokens: not set yet.
