# Security policy

## Status

pipegen is pre-release and the repository is private. This policy describes
how reporting will work once the project is public.

## Supported versions

| Version | Supported |
|---|---|
| Pre-release (0.x, not published) | None yet |

After the first release, the latest minor version is supported.

## How to report a vulnerability

Please do not open a public issue for a security problem.

- Email: pipegen.security@gmail.com
- Once the repository is public, use GitHub private vulnerability reporting
  (the "Report a vulnerability" button on the Security tab). It will be turned
  on at release time.

Include what you found, the pipegen version, and steps to reproduce.

## What to expect

Response times: acknowledgement within 7 days, and a fix or an advisory plan within 30 days.

## Scope

In scope: the pipegen CLI, its bundled data files (`data/`), and its release
workflow. Out of scope: vulnerabilities in third-party tools that pipegen only
reports on, unless pipegen's own handling of them is unsafe.
