# netrecon

**Correlated network diagnostics for engineers.**
DNS, HTTP, TLS, email posture, and CDN inference — joined into findings, not
just dumps of raw records.

🌐 **Live:** <https://netrecon.pages.dev>
📚 **Blog:** <https://netrecon.pages.dev/blog>
🔌 **MCP server:** <https://netrecon.pages.dev/mcp>

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Lighthouse 100](https://img.shields.io/badge/Lighthouse-100%2F100-brightgreen)](https://netrecon.pages.dev/)

---

## What it is

A static-first site + edge functions that take a **domain, IP, or URL** and
return a correlated report:

- **Raw data:** DNS records, HTTP redirect chain, TLS cert chain, email posture.
- **Interpreted findings:** rules that combine signals across modules (e.g.
  *CDN response headers are present but A-record ASN doesn't match the CDN —
  origin may be directly exposed*).
- **Likely root causes** with severity.
- **Reproducible commands:** every finding ships with the exact `dig` / `curl` /
  `openssl` that verifies it.
- **Machine-readable JSON** at `/api/analyze`.
- **MCP server** at `/api/mcp` — same tools, agent-ready.

## What it is not

- Not a commodity "dig in a browser" site.
- Not a paid-API aggregator.
- Not a monitoring tool (no dashboards, no alerts, no leaderboards).
- **No ads. No email capture. No tracking beyond cookieless page analytics.**

## Example

```
$ curl -s 'https://netrecon.pages.dev/api/analyze?input=example.com' | jq '.findings[:3]'
[
  {
    "id": "dmarc.policy.weak",
    "severity": "warning",
    "title": "DMARC policy is 'none' — no enforcement",
    "evidence": { "record": "v=DMARC1; p=none; rua=mailto:..." },
    "reproduce": "dig +short TXT _dmarc.example.com"
  },
  ...
]
```

## Architecture

```
 ┌──────────────────┐    ┌────────────────────────┐    ┌────────────────────┐
 │  Astro (static)  │ -> │  Cloudflare Pages CDN  │    │  Pages Functions   │
 │  src/pages       │    │  (UI + blog + assets)  │    │  functions/api/*   │
 └──────────────────┘    └────────────────────────┘    │  analyze / compare │
                                                      │  mcp / whoami      │
                                                      └──────────┬─────────┘
                                                                 │
                      ┌──────────────────────────────────────────┴─────┐
                      │ Providers (server-side, best-effort)           │
                      │ DoH · Certspotter / crt.sh · Team Cymru        │
                      │ ipwho.is · Shodan facets · Browser Rendering   │
                      └────────────────────────────────────────────────┘
```

Everything interactive runs at the Cloudflare edge. No origin server, no
container. See [`docs/roadmap.md`](./docs/roadmap.md) for phase plan.

## Tool registry + MCP

The same `TOOLS` registry in [`src/lib/tools.ts`](./src/lib/tools.ts) drives:

1. The web UI
2. The HTTP API (`/api/analyze`, `/api/compare`, `/api/tools`, `/api/whoami`)
3. The **Model Context Protocol** server at `/api/mcp`

Claude Desktop / Cursor / VS Code config snippets live on
[`/mcp`](https://netrecon.pages.dev/mcp). See [`docs/mcp-plan.md`](./docs/mcp-plan.md).

## Local development

Requires Node 18.17+ and npm.

```bash
git clone https://github.com/Yossibh/netrecon.git
cd netrecon
npm install
npm run dev          # Astro dev server — UI only (no Pages Functions)
npm run preview      # wrangler pages dev ./dist — full stack locally
npm test             # vitest, 116+ tests
npm run typecheck
```

## Deploy your own

Fork, then in Cloudflare Pages:

- **Build command:** `npm run build`
- **Build output directory:** `dist`
- `functions/` is auto-detected as Pages Functions.

Optional environment variables:

| Variable | What it unlocks | Where to get it |
|---|---|---|
| `SHODAN_API_KEY` | Exposure intel panel (ports, products, CVEs, TLS versions) | <https://account.shodan.io> |

None are required — netrecon degrades gracefully when a provider key is missing.

## Trust posture

This is a **security tool that sends outbound probes on behalf of callers**,
so the threat model and mitigations are public:

- **Threat model:** [`docs/security.md`](./docs/security.md)
- **Non-goals:** ads, email-gated reports, leaderboards, uptime monitoring
- **Analytics:** Cloudflare Web Analytics (cookieless, no PII)

If you find a vulnerability, please use [private disclosure](./SECURITY.md).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). TL;DR: tests must pass, no secrets in
code, keep the /about promises truthful.

## License

[MIT](./LICENSE) — built by [Yossi Ben Hagai](https://yossibh.github.io/)
([LinkedIn](https://www.linkedin.com/in/yossibenhagai/)).
