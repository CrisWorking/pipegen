# ZAP fixtures (G15a round 5)

Real reports of the pinned ZAP image, captured on 2026-11-06 for the gate's ZAP reader (`gate/src/zap.ts`) and the nightly
ZAP Automation Framework (AF) active scan. The gate tests never run ZAP. The files are byte-for-byte what ZAP wrote: no
re-indent, no edit.

## Image

- `zaproxy/zap-stable@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6`, the `zap-baseline` entry's
  `pin.digest` in `data/reviewed-tools.yml` (tag 20261016, ZAP 2.17.0). Pulled by digest with Docker Desktop 29.2.1;
  `docker image inspect` gave the same RepoDigest and image id. The reports say `"@version": "2.17.0"`.
- Every run: `docker create --pull=never --security-opt no-new-privileges --cap-drop ALL --network <net> <image> <command>`,
  the work folder copied in with `docker cp -a` to `/zap/wrk`, `docker start -a`, the report copied out. The image's own user
  (`zap`), as the rendered step runs it. The only difference from the rendered step is the network: a user-defined docker
  network (`pgzap-net`) with the targets at `http://clean:8080` and `http://vuln:8080`, where CI uses `--network host` and
  `http://127.0.0.1:<port>`.

## Targets (`targets/`, local test fixtures only, never deployed)

Both ran with `python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca` (`python /app.py`).

- `targets/clean.py`: one static page with strict headers (CSP `default-src 'none'`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Cache-Control: no-store`, the cross-origin headers) and no version in `Server`.
- `targets/vuln.py`: a reflected XSS at `/search?q=` and no security headers.

## Reports

| File | Command (in `/zap/wrk`) | Target | Exit | Alerts (pluginid riskcode) |
|---|---|---|---|---|
| `baseline-clean.json` | `zap-baseline.py -t http://clean:8080 -c zap-baseline.conf -J zap.json -z -silent` | clean | 0 | none: one site, `alerts: []` |
| `baseline-alerts.json` | same, `-t http://vuln:8080` | vuln | 2 (WARN) | 10038 2, 10020 2, 10036 1, 10021 1 (10 instances) |
| `af-active-clean.json` | `zap.sh -cmd -silent -autorun /zap/wrk/zap-active.yaml` | clean | 0 | none: one site, `alerts: []` |
| `af-active-alerts.json` | same | vuln | 0 | 40026 3, 40012 3, 10038 2, 10020 2, 10036 1, 10021 1 (13 instances) |

- `zap-baseline.conf` is the entry's pinned config text ("# pipegen's pinned ZAP baseline rules: the defaults, nothing ignored").
  It is the merge-layer command of the `zap-baseline` entry (`step.cli.command`, the `-t` slot filled).
- `zap-baseline.py` 2.17.0 runs through the AF itself ("Using the Automation Framework"); its `-J` is the AF `report` job with
  the `traditional-json` template, so the baseline and the AF active reports share one format.
- The AF exits 0 with findings (alerts never fail a plan). Its plan errors exit 1.
- Not kept as a file, a target that does not answer (`http://down:8080`, no such host): `zap-baseline.py` exits 3 and the AF
  exits 1, and neither writes a report. The rendered run step fails on both, so a dead target is never a clean scan.

## The AF plan (`plans/af-active-capture.yaml`)

The plan the AF reports were taken with, `<target>` standing for `clean` or `vuln`: `passiveScan-config`
(`maxAlertsPerRule: 10`, `enableTags: false`, as `zap-baseline.py` writes it), `spider` (5 min), `passiveScan-wait` (5 min),
`activeScan` (policy: default strength and threshold `medium`, no rule changed; `maxRuleDurationInMins: 5`,
`maxScanDurationInMins: 30`), and `report` (`traditional-json`, `/zap/wrk/zap-active.json`). `env.parameters`:
`failOnError: true`, `failOnWarning: false`. The plan pipegen renders (`src/engine/zap-active.ts`) is this plan with the
target URL of the running app.

## sha256

```
e685ff3c9ed983b7fccd7ab220c5b4e4d619d61915f268d7e33941b25a4b1b7d  af-active-alerts.json
a3b5f66c25245200825c7012cd2952ca90ccd3c090609511ba875f9279ea5a93  af-active-clean.json
497813b5706a9f1207348b676cdffc4b598f39b9cb976a6340dedddc244e09b6  baseline-alerts.json
ba56b4f9ef74e711d1c1193df7d26961562c654ab6916c8c8bc9450acb5ba74b  baseline-clean.json
00cf5a65437b9d0dfb1c968595f84a03e5826ccaf02d9ddd2048d083a2ab715e  plans/af-active-capture.yaml
```

`zap-traditional-json.json` is older (Plan C): a unit-test output of the ZAP reports add-on, see `../sarif/README.md`.
