# Example: `pipegen audit` output

> ⚠️ **Example, not real yet.** pipegen has no code yet. This shows what the v0.1 audit is designed to print, for a made-up project (`acme/shop-api`: Node/TypeScript + Postgres, private repo on GitHub Free).

```text
$ npx pipegen@0.1.0 audit

pipegen audit · acme/shop-api · read-only (nothing was changed)

Verdict: 4 of 4 layers have gaps · 2 are serious · 1 secret found in your files

⚠ SECRET IN YOUR CURRENT FILES  (fix this first)
  config/dev.ts   looks like a Stripe key (sk_live_…)
  → Revoke it in Stripe and move it to a GitHub secret. It is already in git history.

YOUR GITHUB PLAN  (Free · private repo)
  ✗ Merge locks (branch protection)   need GitHub Pro (personal) or Team (organisation)
  ✗ Deploy environments / signing     need GitHub Pro or Team
  ✓ Everything else below works on your plan

FOUR LAYERS
  Layer         Status       What covers it today       Missing
  1 Pre-commit  ✗ missing    —                          secret scan before commit
  2 Push        ⚠ partial    npm test (on push)         secret scan, code scan, dependency scan, lint
  3 Merge       ⚠ partial    npm test (on PR)           image scan, attack test on the running app,
                                                         gate, merge lock (plan)
  4 Deploy      ✗ missing    deploy.yml (Vercel)        verify-first before deploy, SBOM

  Why it matters
  • No secret scan before commit → a leaked key stays in git history forever.
  • No dependency scan → known-vulnerable libraries reach production unnoticed.
  • Deploy runs without checking the gate → a failing commit can still go live.

WHAT PIPEGEN WOULD ADD  (reviewed tools only)
  secrets     gitleaks          pre-commit + push + merge
  code scan   Semgrep CE        push + merge
  deps        osv-scanner       push + merge
  image       Trivy             merge
  attack      OWASP ZAP base    merge (against the running app)
  hooks       lefthook          your computer
  deploy      verify-first job added to deploy.yml (your deploy itself is not changed)

WHAT PIPEGEN WOULD CREATE
  Dockerfile + .dockerignore      none found (needed for image scan and attack test)
  docker-compose.pipegen.yml      your app uses Postgres (found: prisma, DATABASE_URL)
  starter tests                   — you already have tests (jest), kept as they are

COSTS  (estimates · basis below)
  Setup (one time)        ~140 GitHub Actions minutes   hard limit 280
  After setup, monthly    ~610 minutes  (31% of your free 2,000)   ← based on 42 pushes and 19 PRs in the last 30 days
  AI (full run only)      ~$1.10 – $3.30 with Claude · $0 with a local model (Ollama)
  Time                    ~25 – 50 minutes for the full run
  Basis: 4 min per job until measured · 1 proof run + 2 dispute runs · 30% fix buffer

PERMISSIONS THE FULL RUN WOULD NEED  (only on: shop-api, pipelines, pipegen-proof-shop-api)
  Contents, Workflows, Secrets, Variables, Actions, Administration (settings after merge)
  → classic broad tokens are refused

NEXT STEP
  Full setup for Node/TypeScript arrives in v0.2:  npx pipegen
  Save this report:  npx pipegen audit --out pipegen-audit.md
```
