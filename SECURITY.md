# Security policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Use GitHub's **Private Vulnerability Reporting** instead:

1. Go to the [Security tab](https://github.com/Yossibh/netrecon/security) of
   this repo.
2. Click **Report a vulnerability**.
3. Describe the issue, impact, and (if possible) reproduction steps.

You can expect:

- An acknowledgment within a few days.
- A fix or formal decline within a reasonable window, typically under 14 days
  for high-severity issues.
- Credit in the release notes if you'd like.

## Scope

In scope:

- `netrecon.pages.dev` and its `/api/*` endpoints
- Source code in this repository
- The published GitHub Action (when released)

Out of scope:

- Denial-of-service via CPU or bandwidth exhaustion — we rely on Cloudflare's
  built-in protections plus in-code rate limits; see
  [docs/security.md](./docs/security.md).
- Vulnerabilities in upstream providers (Shodan, crt.sh, ipwho.is, etc.).
- Social engineering or physical attacks.

## Design-time security posture

netrecon is an unauthenticated internet-facing service that runs outbound
network probes on behalf of arbitrary callers. The threat model, mitigations,
and residual risks are documented in
[`docs/security.md`](./docs/security.md).

Highlights:

- SSRF guards on all probe paths.
- Per-IP rate limiting via Pages Functions middleware.
- No secrets ever leak into responses (errors are scrubbed).
- Shodan integration is best-effort; absence degrades gracefully.

## Supported versions

Only the `main` branch is supported. netrecon deploys continuously to
`netrecon.pages.dev`; there are no long-lived release branches.
