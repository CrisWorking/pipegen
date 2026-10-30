#!/bin/sh
# Builds the clean repo (usage: plant-clean.sh <dir>): the same tools over it must report nothing (test/fixtures/sarif/clean).
set -e
D=$1; rm -rf "$D"; mkdir -p "$D"; cd "$D"
git init -q -b main .; git config user.email t@example.com; git config user.name t
mkdir -p py go k8s
printf '# clean fixture\n' > README.md
printf 'def add(a, b):\n    return a + b\n' > py/ok.py
printf 'module example.com/clean\n\ngo 1.22\n' > go/go.mod
printf 'package main\n\nfunc main() {}\n' > go/main.go
printf 'FROM alpine:3.20.3\nUSER 1000\nHEALTHCHECK CMD ["true"]\n' > Dockerfile
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  a: b\n' > k8s/ok.yaml
printf 'console.log("hello");\n' > index.js
cat > package-lock.json <<'J'
{ "name": "clean", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": { "": { "name": "clean", "version": "1.0.0", "dependencies": { "is-number": "7.0.0" } },
    "node_modules/is-number": { "version": "7.0.0", "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz" } } }
J
git add -A; git commit -qm "clean fixture repo"
