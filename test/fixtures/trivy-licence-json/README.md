# trivy licence JSON fixtures (G15a, G11-2)

Captured offline on 2026-11-06 with the pinned trivy 0.76.0 (the reviewed archive `trivy_0.76.0_Linux-64bit.tar.gz`,
sha256 e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7), run in a network namespace with no network
(`unshare -rn`), with pipegen's pinned trivy config and the reviewed licence command:

`trivy fs --config trivy.yaml --disable-telemetry --skip-version-check --skip-check-update --scanners license --format json --list-all-pkgs --output <file> --exit-code 10 .`

| File | Scanned folder | Exit | What it shows |
|---|---|---|---|
| `composer.json` | `php/composer.lock` with acme/gpl (GPL-3.0-only), acme/mit (MIT), acme/weird (SomeWeirdLicense-1.0), acme/nolicence (no `license` key), acme/emptylicence (`license: []`) | 10 | the `license` result lists the three packages with a licence (HIGH restricted, LOW notice, UNKNOWN unknown); the two packages with no licence data appear only in the `lang-pkgs` result, with no `Licenses` |
| `npm.json` | `package-lock.json` (v3) with left-pad (WTFPL) and nolic (no `license`) | 10 | WTFPL is CRITICAL forbidden; nolic has no `Licenses` |
| `empty.json` | a folder with no lockfile | 0 | no `Results` key |
