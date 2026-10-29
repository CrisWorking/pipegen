# Roadmap

Each version is **complete** for what it covers. pipegen never does half a job: projects it can't fully handle yet get the audit only, with a clear message.

| Version | What you get | Projects |
|---|---|---|
| **v0.1** | `pipegen audit`: a read-only report of your pipeline's gaps, what pipegen would add and create, and what it would cost. No AI needed (optional `--ai` for smarter suggestions, with consent). | Any GitHub repo |
| **v0.2** | `pipegen`: the full job. Tools chosen and proven on real runners, missing pieces created (Dockerfile, compose, tests), four protection layers, one PR, rules applied after you merge, plus `verify` and `uninstall` | Node/TypeScript, one package |
| **v0.3** | Keep or switch your test framework (with proof that every test result stays the same), the weekly watcher, Slack alerts, and **AI code review** comments on every PR (advisory, never blocking) | Same |
| **v0.4** | Python, then monorepos (up to 10 services) | More stacks |

Status today: **v0.1 is built internally and not published yet.** `pipegen audit` (read-only) works; nothing is on npm, and the public release happens only when v0.4 is done.
