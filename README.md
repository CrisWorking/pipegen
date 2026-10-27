# pipegen *(working name)*

**Add secret scanning, code scanning, tests and signed builds to your GitHub repo with one command.**
For small teams with nobody dedicated to security, DevOps or code quality.
It opens one pull request. You review it. It never touches your app code or your `main` branch.

> **Status: early. Design only, no code yet.** The first release is `pipegen audit` (read-only). See the [roadmap](docs/roadmap.md).

## What the audit will show you *(example, not real yet)*

```text
$ npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo

Verdict: 4 of 4 layers have gaps · 2 are serious · 1 secret found in your files

FOUR LAYERS
  Layer         Status       What covers it today       Missing
  1 Pre-commit  ✗ missing    —                          secret scan before commit
  2 Push        ⚠ partial    npm test (on push)         secret scan, code scan, dependency scan
  3 Merge       ⚠ partial    npm test (on PR)           image scan, attack test, gate, merge lock
  4 Deploy      ✗ missing    deploy.yml (Vercel)        verify-first before deploy, SBOM

COSTS
  After setup, monthly    ~610 GitHub Actions minutes (31% of your free 2,000)
```

[See the full example report →](examples/audit-example.md)

## What the full run does (v0.2)

pipegen reads your project, works out what a complete pipeline needs, **creates what's missing** (like a Dockerfile or tests), **proves everything works on real GitHub runners** before you see anything, and opens **one PR** with a plain-English `PIPEGEN.md` explaining every choice.

It protects four stages: **pre-commit → push → merge → deploy**.

## What it touches, and what it never touches

| ✅ It does | ❌ It never does |
|---|---|
| Adds workflow files, configs, a Dockerfile/compose/tests when they're missing | Edit your application's source code |
| Opens **one PR** (you review and merge) | Push to your `main` branch |
| For private projects: uses two **private** helper repos (`pipelines`, `pipegen-proof-<repo>`) | Make any repo public, or suggest it |
| Stores the keys you give it as **GitHub secrets** | Write a secret into a file, log, PR or chat |
| Applies merge rules **after** you merge the PR | Deploy your app |

## Permissions and cost (honest numbers before you start)

- **Access:** a GitHub App or fine-grained token limited to the repos involved. Broad classic tokens are refused by default.
- **Shown before anything runs:** setup Actions minutes (hard limit 2× the estimate), **monthly** minutes afterwards, approximate AI cost (or "free" with a local model), and approximate time.
- **GitHub Free + private repos:** merge locks need GitHub Pro (personal) or Team (organisation), and required deploy reviewers on private repos need GitHub Enterprise. pipegen checks what your repo really allows, sets up everything else and tells you exactly what's missing. Image signing works on Free private repos too, when pipegen can confirm the signing environment's branch rule (only your default branch may use the key).

## Commands *(planned)*

```bash
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo
                          # read-only report; run it from OUTSIDE the repo, exact version, explicit registry
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo --out report.md
                          # also save the report as Markdown (outside the repo; --json prints JSON instead)
npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./my-repo --ai
                          # also ask an AI for extra checks and tools to mention, after it shows what it would send
                          # and asks you (default No)
```

`audit --ai` needs Linux or macOS for now (WSL works): it checks your code with a pinned gitleaks binary before
anything is sent, and that binary exists for those systems only.

Later versions add the full job (one PR), then `finish` (after you merge: merge rules, signing key and dates), `verify`
(read-only: checks nobody weakened the pipeline files) and `uninstall`. Their exact commands will be shown here when
they exist; until then no other pipegen command is safe to copy, because the npm name isn't published yet.

## Read more

- [Design](docs/design.md)
- [Threat model](docs/threat-model.md): who could attack, and what stops them
- [Roadmap](docs/roadmap.md)

## Licence

[Apache-2.0](LICENSE).
