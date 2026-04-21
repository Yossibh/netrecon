# Security review - netrecon

Scope: all public endpoints (`/api/analyze`, `/api/compare`, `/api/whoami`,
`/api/health`, `/api/tools`) and the three public HTML pages (`/`, `/compare`,
`/decode`).

Threat model. netrecon is an unauthenticated, internet-facing service that runs
outbound network probes on behalf of arbitrary callers. The interesting abuse
vectors are therefore:

1. Using netrecon as a **reflector / amplifier** to attack a third party.
2. Using netrecon to probe networks the caller shouldn't reach (classic SSRF).
3. Burning the operator's **upstream credits** (Shodan is paid).
4. Burning the operator's **Worker CPU budget** (free-tier quota).
5. Rendering attacker-controlled strings unsafely (reflected / stored XSS).
6. Leaking operator secrets via error paths.

## Findings and mitigations

### 1. SSRF into private ranges - MITIGATED
**Finding.** `/api/analyze` will accept arbitrary domains, bare IPs, and full
URLs. Before the fix, input like `https://169.254.169.254/` or `https://10.0.0.1/`
was forwarded to `fetch()`.

**Partial natural mitigation.** Cloudflare Workers `fetch()` does not route to
the worker's local network - there is no "inside" network to pivot into from a
Pages Function. So classic AWS-metadata-style SSRF is not exploitable.

**Residual risk.** An attacker could still use netrecon as an
attribution-laundering proxy for probing someone's publicly-routed "private"
range, or target cloud metadata IPs in log-forwarding situations where upstream
observers misinterpret the traffic.

**Fix (shipped).** `src/lib/security.ts::validateHost()` rejects:
- RFC1918 (`10/8`, `172.16/12`, `192.168/16`)
- RFC6598 CGNAT (`100.64/10`)
- loopback (`127/8`, `::1`)
- link-local incl. metadata (`169.254/16`, `fe80::/10`)
- IPv6 ULA (`fc00::/7`)
- multicast, benchmark, TEST-NETs, documentation ranges
- IPv4-mapped IPv6 (e.g. `::ffff:127.0.0.1`)
- hostnames: `localhost`, `*.local`, `*.internal`, `*.lan`, `*.corp`, etc.
- non-http(s) schemes (file:, gopher:, javascript:)

**Defense in depth.** The same check runs a second time in `http.ts` right
before `fetch()`, including on every redirect Location header - so an
attacker cannot bypass the input-level check by making a public host 301 to
`http://169.254.169.254`.

### 2. Amplification / DoS of third parties - MITIGATED
**Finding.** No rate limiting on `/api/analyze` or `/api/compare`. Each call
triggers one HTTP fetch to the user-supplied target plus several third-party
API calls. Amplification factor per request is modest (1:1 against the target),
but an attacker with a botnet could sustain attack traffic using netrecon's IP
as the source.

**Shipped mitigations.**
- Input size cap (`MAX_INPUT_LENGTH = 2048`).
- HTTP probe timeout `FETCH_TIMEOUT_MS = 8000`ms.
- `MAX_REDIRECTS = 8`; redirect-loop detection.
- User-Agent is explicit (`netrecon/0.1 (+https://netrecon.pages.dev)`), so the
  target can filter us out if we misbehave.

**Recommended (operator action - not code).** ~~Enable Cloudflare Rate Limiting
rules in the dashboard~~ - *not available for `*.pages.dev` (shared zone).*

**Shipped: in-code rate limiter** via Pages Functions middleware
(`functions/api/_middleware.ts`) using the Cloudflare Cache API as a per-colo
cross-invocation counter:

| Path family         | Limit        |
| ------------------- | ------------ |
| `/api/analyze`      | 10 req/min   |
| `/api/compare`      | 10 req/min   |
| `/api/whoami`       | 60 req/min   |
| `/api/health`       | unlimited    |
| `/api/tools`        | unlimited    |

Over-limit requests return HTTP 429 with `retry-after` and
`x-ratelimit-{limit,remaining,reset}` headers. Counters are per-colo (not
global) - a distributed low-rate flood that spreads across many CF colos is
caught upstream by Cloudflare's DDoS layer. Tune thresholds in `policyFor()`.

A stronger global rate-limiter (Durable Object or KV-backed token bucket) is on
the roadmap but not required for launch.

### 3. Upstream credit burn (Shodan) - MITIGATED
**Finding.** Shodan's `/shodan/host/{ip}` costs 1 query credit per call. An
attacker who knows netrecon is wired to Shodan could spam unique IPs to drain
the operator's credit pool.

**Shipped mitigations.**
- The input-size cap and SSRF guard bound the set of IPs that are actually
  forwarded to Shodan.
- Shodan calls are **best-effort and skipped gracefully**: `skipReason` is
  surfaced, never thrown, so a missing key or a rate-limit failure doesn't
  cascade.
- Domain queries use the **free** `/shodan/host/count` endpoint (zero query
  credits). Only host-lookup for direct IP input consumes credits.

**Recommended.** Combined with the shipped in-code rate limiter (10/min/IP per
colo), worst-case single-IP Shodan consumption is bounded to ~10 credits/min
per colo. Acceptable for a personal plan; tighten `policyFor('/api/analyze')`
to 3/min if the account has a lower monthly cap.

### 4. Worker CPU-time abuse - MITIGATED
**Finding.** Workers free tier: 100k requests/day, 10ms CPU/request. netrecon
uses concurrent fetches so wall time (not CPU time) dominates.

**Shipped mitigations.** Input size cap; per-provider timeouts in `ip.ts`,
`tls.ts`, `shodan.ts`; 8s HTTP probe timeout; max 8 redirects.

### 5. XSS on rendered data - MITIGATED
**Finding.** The analyze page renders arbitrary HTTP headers, TLS
subjects/issuers, and other strings pulled from target responses.

**Current state.** All user-facing rendering goes through `document.createTextNode`
(via the `h()` helper) or `JSON.stringify`. `innerHTML` is only used for a
controlled progress-prompt string built from `escapeHtml(target)`. The `html:`
attribute in `h()` is never called with attacker-controlled data in the
shipped code.

**Action.** None required. Guidance added: never introduce `innerHTML` for
provider-sourced data.

### 6. Secret leakage - MITIGATED
- `env.SHODAN_API_KEY` lives in Pages secrets; never logged.
- Error paths return `err.message` via `/api/analyze` - this is the error text
  generated by our own providers (sanitized: no secret is ever included in
  thrown errors). Upstream provider errors say "HTTP 401" etc., not tokens.
- Cloudflare injects `cf-ray` et al. on subrequest responses - we strip these
  in `http.ts` so we don't attribute them to the target.

### 7. CORS `*` on public APIs - ACCEPTED
All API endpoints are public read-only diagnostics. Setting
`access-control-allow-origin: *` lets other sites embed and script against us;
combined with rate limiting, that's a feature, not a bug.

### 8. Operator secret hygiene - ADDRESSED
All upstream credentials (`SHODAN_API_KEY`, `CLOUDFLARE_API_TOKEN`) live as
Pages environment secrets. They are never committed to source, never emitted
in responses, and never logged. Rotation policy: at least annually, or
immediately on any suspected exposure.

## Operator checklist
- [x] ~~Enable Cloudflare Rate Limiting rule for `/api/*`~~ - shipped in-code via `functions/api/_middleware.ts`.
- [ ] Rotate `SHODAN_API_KEY` at least annually.
- [ ] Monitor Shodan monthly credit usage; tune thresholds in `_middleware.ts::policyFor()` to match.
- [ ] Re-run `npx vitest run` after any change to input handling or
      `http.ts` - the SSRF guard has dedicated tests under `tests/security.test.ts`.
