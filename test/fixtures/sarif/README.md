# SARIF and ZAP fixtures (Plan C, C1a)

Real output of the pinned tools, captured on 2026-10-29 for the gate's parsers (`gate/src/sarif.ts`, `gate/src/zap.ts`).
The gate tests never run a scanner. Nothing here is a real credential: the planted ones are derived from a sha256 at
capture time (`capture/plant.sh`), and every secrets scan ran with `--redact`, so the files hold `REDACTED`.

## How they were captured

- Tools: the pinned release binaries, downloaded and checked against the reviewed entry's sha256 (`data/reviewed-tools.yml`
  `pin.checksum`, the archive) before use. betterleaks and gitleaks came from `ensurePinnedBinary`'s cache.
  Docker is not available in this WSL, so the docker entries (semgrep, zap) are covered as noted below.
- Argv: the reviewed command of each entry (its `step.cli.command`), plus the entry's pinned `--config` file where it has one.
  Differences are in the table.
- Planted repo: `capture/plant.sh` (findings) and `capture/plant-clean.sh` (nothing to find), both small git repos.
- Workspace: every tool ran inside `unshare -rm` with the repo bind-mounted at `/home/runner/work/fixture/fixture`, `HOME=/home/runner`,
  the tool binaries at `/home/runner/bin` and the semgrep rules at `/home/runner/pipegen-rules`. That is why no local path is in a fixture,
  and why the tests pass `workspace: '/home/runner/work/fixture/fixture'` (osv-scanner and ruff write `file://` + the absolute path).
- Formatting only: the files that a tool wrote on one line (kube-linter, semgrep, hadolint, ruff when clean, and `nuclei`, which uses tabs)
  were re-indented to two spaces with Python's `json.dumps(indent=2, ensure_ascii=False)`. Data and key order are unchanged. This is needed
  because pipegen's own "no secret-like literal under test/" check refuses a single line over its length limit.
- `test/no-secret-literals.test.ts` now excuses exactly two benign strings of real tool output before it checks: osv-scanner's empty
  redaction-tokens array and trivy's already-masked match line for the planted GitHub token.

## Planted-repo fixtures (`*.sarif`)

| Fixture | Tool and version | Command (reviewed, differences in the last column) | Exit | Results | Differences from the reviewed run |
|---|---|---|---|---|---|
| `betterleaks.sarif` | betterleaks 1.9.0 | `betterleaks git --config bl.toml --no-banner --ignore-gitleaks-allow --redact --report-format sarif --report-path betterleaks.sarif --exit-code 10 .` | 10 | 2 | none. `bl.toml` is the entry's `[extend] useDefault = true`. |
| `gitleaks.sarif` | gitleaks 8.30.1 | same flags, `gitleaks git ...` | 10 | 2 | none |
| `semgrep.sarif` | semgrep 1.181.0 (pip venv) | `semgrep scan --metrics=off --disable-version-check --max-target-bytes=0 --config <rules> --sarif --output semgrep.sarif` | 0 | 7 | the reviewed entry runs the docker image (digest in the entry); it cannot run here, so the same version from a venv ran. Rules: semgrep-rules commit 17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9 (archive sha256 9dfe6866fbecd557f507078cb79721a9eb8f4764fc2f6163648ea1320be25933, checked), folders `javascript/lang/security`, `javascript/express`, `python/lang/security` at `/home/runner/pipegen-rules`. |
| `semgrep-timeout.sarif` | semgrep 1.181.0 | as above with `--config .../javascript/lang/security` over a repo whose only file is a 20 MB padded `src/huge.js` | 0 | 0 | the real Timeout shape from review-6d-r2: `executionSuccessful: true`, no results, `toolExecutionNotifications` with `Timeout` warnings |
| `osv-scanner.sarif` | osv-scanner 2.7.0 | `osv-scanner scan source --recursive --config osv.toml --format sarif --output osv.sarif .` | 1 | 8 | queries api.osv.dev when it runs, so the vulnerability list (8, including one critical) is the state of 2026-10-29. `osv.toml` is the entry's one-line comment config. |
| `trivy-config.sarif` | trivy 0.76.0 | `trivy config --config trivy.yaml --disable-telemetry --skip-version-check --skip-check-update --format sarif --output ... --exit-code 10 .` | 10 | 36 | none (checks are the ones embedded in the binary: "falling back to embedded checks") |
| `trivy-image.sarif` | trivy 0.76.0 | `trivy image --config trivy.yaml --disable-telemetry --skip-version-check --skip-check-update --format sarif --output ... --exit-code 10 --input image.tar` | 10 | 3 | no docker: the image is a hand-built docker-archive (`capture/mkimage.py`, alpine 3.10.2 with an old musl and busybox and one planted token), read with `--input`. A real image run names the image where this one names the archive path. trivy downloaded its vulnerability database from its default mirror at run time. |
| `trivy-licence.sarif` | trivy 0.76.0 | `trivy fs ... --scanners license --severity HIGH,CRITICAL --format sarif ... --exit-code 10 .` | 10 | 2 | the licences come from `php/composer.lock`: `trivy fs` reads no licence from `node_modules/*/package.json` without `--license-full`, and a lockfile of another kind lists none |
| `trivy-licence-unfiltered.sarif` | trivy 0.76.0 | the same without `--severity HIGH,CRITICAL` (the S9 change), over a lockfile with one GPL-3.0-only and one unknown licence | 10 | 2 | an Unknown licence is level `note`, rule number `0.0`, tag `UNKNOWN`: the parser reads it as info |
| `hadolint.sarif` | hadolint 2.15.1 | `hadolint --no-color --failure-threshold warning --format sarif --output hadolint.sarif Dockerfile` | 1 | 6 | `Dockerfile` appended (the renderer adds the file) |
| `kube-linter.sarif` | kube-linter 0.8.3 | `kube-linter lint --fail-if-no-objects-found --fail-on-invalid-resource --format sarif --output kube-linter.sarif k8s` | 1 | 5 | `k8s` appended. **`executionSuccessful` is `false` here because it found something** (true on the clean run). |
| `nuclei.sarif` | nuclei 3.11.1 | `nuclei -duc -t <one template> -severity medium,high,critical -ni -u http://127.0.0.1:<port> -sarif-export nuclei.sarif` | 0 | 1 | one template from the pinned nuclei-templates v10.5.0 archive (sha256 80fbabce..., checked), `http/exposures/configs/git-config.yaml`, not the whole tree; the target is a local `python3 -m http.server` serving the planted repo, so `/.git/config` answers. **`executionSuccessful` is `false` although the run worked.** |
| `ruff.sarif` | ruff 0.17.1 | `ruff check --no-cache --config ruff.toml --output-format sarif --output-file ruff.sarif` | 1 | 1 | none. `ruff.toml` is the entry's (C901 at 15). The uri is `file://` + the absolute path. |
| `gosec.sarif` | gosec 2.29.0 | `gosec -fmt sarif -out gosec.sarif -track-suppressions ./...` | 1 | 2 | run inside the `go/` module folder, so the uris are `main.go` |
| `bandit.sarif` | bandit 1.9.4 | `bandit --recursive --format sarif --output bandit.sarif .` | 1 | 4 | pip install of the three reviewed wheels (bandit, sarif-om 1.0.4, jschema-to-python 1.2.3); their sha256 equal the entry's. Bandit's own dependencies were resolved by pip, unpinned. Python 3.12.3. |

## Clean-run fixtures (`clean/*.sarif`)

The same commands over `capture/plant-clean.sh`'s repo: a real clean scan, to prove `results: []` is not a tool error.
betterleaks, gitleaks, semgrep, osv-scanner, trivy-config, trivy-licence, hadolint, kube-linter (`executionSuccessful: true`, `results: []`),
ruff, gosec and bandit all exit 0 and write a SARIF with `"results": []`.

Not captured, because the tool writes **no file**:
- nuclei with no result: exit 0 and no `-sarif-export` file (measured: "No results found").
- osv-scanner with no package source: exit 128, no file ("No package sources found").
- kube-linter with no valid object: exit 1, no file ("no valid objects found").
- trivy-image: no clean image was captured (an image with no known vulnerability needs a current OS image).

## ZAP (`../zap/zap-traditional-json.json`)

Not run: `zap-baseline.py` needs docker. The file is a real report of the same format (`-J` writes ZAP's traditional-json report):
`addOns/reports/src/test/resources/org/zaproxy/addon/reports/resources/basic-traditional-json.json` of
https://github.com/zaproxy/zap-extensions at commit `10c6852728106417e2085fc2c2acbb1074d3fd6c` (the head of `main` on 2026-10-29),
sha256 `d05d5e466cebdb791ad0c25d58dde92d6e79ed5a1b27d44bf889ec0b8172b995`, fetched from raw.githubusercontent.com.
It has one site, one alert (pluginid 1, riskcode 3) with two instances of one URL, and `@version: "Dev Build"`.

## What the tools write (measured), for the parser

| Tool | `invocations` | `executionSuccessful` | Severity at the source |
|---|---|---|---|
| betterleaks, gitleaks | none | none | none (the parser says critical) |
| semgrep | one, `toolExecutionNotifications: []` | true | rule `defaultConfiguration.level` (result level absent) |
| osv-scanner | `[]` | none | rule `security-severity` |
| trivy-* | none | none | rule `security-severity` (and a tag with the word) |
| hadolint | none | none | result `level` |
| kube-linter | one | **false when it found something** | none at all (no level, no number) |
| nuclei | one | **always false** | rule `security-severity` |
| ruff | none | none | result `level` (always `error`) |
| gosec | none | none | the severity word in the rule's `tags`; the `level` is `error` for MEDIUM too |
| bandit | one | true | result `properties.issue_severity` |
