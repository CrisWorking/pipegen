#!/bin/sh
# Builds the planted repo (usage: plant.sh <dir>). Every secret-like value is derived at run time from a sha256
# (never written as a literal), and no committed file under test/ holds one.
set -e
D=$1; rm -rf "$D"; mkdir -p "$D"; cd "$D"
git init -q -b main .; git config user.email t@example.com; git config user.name t
mkdir -p src k8s terraform go py php
mk() { printf '%s' "$1" | sha256sum | tr 'a-f' 'A-F' | head -c 18; printf '%s' "$1" | sha256sum | head -c 18; }
A="gh""p_$(mk one)"; Bs="gh""p_$(mk two)"
printf 'export const first = "%s";\nexport const second = "%s";\n' "$A" "$Bs" > src/config.js
cat > src/app.js <<'JS'
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  cp.exec('ls ' + req.query.dir, (err, out) => res.send(out));
});
app.get('/eval', (req, res) => { res.send(String(eval(req.query.code))); });
app.listen(3000);
JS
cat > Dockerfile <<'DF'
FROM node:latest
RUN apt-get update && apt-get install -y curl
ADD . /app
WORKDIR /app
CMD node src/app.js
DF
cat > k8s/deploy.yaml <<'Y'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels:
    app: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: nginx:latest
          ports:
            - containerPort: 80
Y
cat > terraform/main.tf <<'T'
resource "aws_s3_bucket" "data" {
  bucket = "pipegen-fixture-bucket"
  acl    = "public-read"
}
resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
T
printf 'module example.com/fixture\n\ngo 1.22\n' > go/go.mod
cat > go/main.go <<'G'
package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	h := md5.New()
	h.Write([]byte("x"))
	fmt.Printf("%x\n", h.Sum(nil))
}
G
cat > py/app.py <<'P'
import pickle
import subprocess


def run(cmd):
    return subprocess.call(cmd, shell=True)


def load(data):
    return pickle.loads(data)
P
python3 - > py/complex.py <<'P'
print("def big(x):")
for i in range(18):
    print(f"    if x == {i}:\n        return {i}")
print("    return -1")
P
cat > package.json <<'J'
{ "name": "fixture", "version": "1.0.0", "dependencies": { "lodash": "4.17.15", "minimist": "1.2.0" }, "license": "MIT" }
J
cat > package-lock.json <<'J'
{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "fixture", "version": "1.0.0", "dependencies": { "lodash": "4.17.15", "minimist": "1.2.0" } },
    "node_modules/lodash": { "version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" },
    "node_modules/minimist": { "version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz" }
  }
}
J
printf '{ "name": "fixture/php", "require": { "acme/gpl": "1.0.0" } }\n' > php/composer.json
cat > php/composer.lock <<'J'
{
  "_readme": ["fixture"],
  "content-hash": "00000000000000000000000000000000",
  "packages": [
    { "name": "acme/gpl", "version": "1.0.0", "license": ["GPL-3.0-only"] },
    { "name": "acme/agpl", "version": "1.0.0", "license": ["AGPL-3.0-only"] },
    { "name": "acme/mit", "version": "1.0.0", "license": ["MIT"] },
    { "name": "acme/none", "version": "1.0.0" }
  ],
  "packages-dev": [], "platform": [], "platform-dev": []
}
J
git add -A; git commit -qm "planted fixture repo"
