# Security Policy

## Reporting a vulnerability

Email **security@intentgate.app** with subject line starting `Security disclosure`.

We confirm receipt within one business day. Embargo: **90 days from confirmed receipt**, or earlier if a patch is available and rolled out to known users, or if the reporter requests it.

PGP fingerprint will be published alongside the documentation site once live; until then, send unencrypted reports to the email above. Do **not** open a public GitHub issue for security reports.

## What we run on this repository

- **Dependabot** alerts on every push, scanning Python (pip) + GitHub Actions for known CVEs. Security updates are auto-proposed as PRs.
- **CodeQL** static analysis on every push and pull request, plus a weekly scheduled scan.
- **Secret scanning** and **push protection** at the GitHub platform level — committed secrets are detected, and pushes that contain them are blocked.

## Supply chain

Releases publish to PyPI via **OIDC trusted publishing** — no long-lived API tokens in CI. Each release derives from a specific Git tag, signed off by GitHub Actions identity.

## Supported versions

The most recent released minor version is supported. Older versions receive security patches at our discretion for **six months** past the next minor release.

## Coordinated disclosure window

We follow a standard 90-day responsible disclosure model. Earlier disclosure happens when:

- A patch is available and rolled out to known users
- The issue is actively exploited in the wild
- The reporter requests earlier publication

## Out of scope

The following are explicitly out of scope for this disclosure program:

- Social engineering of NetGnarus staff or customers
- Physical attacks on infrastructure
- Denial-of-service / volumetric attacks (these are operational concerns, not vulnerabilities)
- Issues in third-party dependencies — please file those with the upstream project. We track upstream advisories via Dependabot and remediate from there.

---

Maintained by **NetGnarus B.V.**, Ijsselstein, The Netherlands (KvK 63319578). Commercial inquiries: <https://intentgate.app/contact>.
