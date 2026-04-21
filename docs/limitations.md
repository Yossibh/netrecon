# Limitations

netrecon is hosted on Cloudflare Workers / Pages Functions. That runtime is a superb fit for HTTPS-based diagnostics at the edge, but it intentionally does not expose several primitives that engineers might expect from a traditional netdiag box.

## Not available in the MVP

### `ping` / ICMP
Workers cannot open ICMP sockets. There is no workaround in the runtime. A hosted ping would require a separate control-plane (e.g. a tiny VM pool) which is out of scope for a free-tier MVP.

### `traceroute`
Same reason as `ping` - raw socket access is not available.

### Arbitrary TCP/UDP port scans
Workers `fetch()` is limited to HTTPS (and a small allowlist of schemes). There is no generic `net.Socket` API. The Cloudflare `connect()` Sockets API is available but restricted to outbound TCP on a limited set of ports; we have chosen not to wire it up in the MVP to keep the tool aligned with its explicit "HTTP-layer diagnostics" scope.

### Live TLS peer handshake
The Workers `fetch()` implementation does the TLS handshake internally and does **not** expose peer certificate details to the calling code. This means we cannot reliably return:
- the actual certificate chain as presented by the origin,
- the OCSP staple,
- certificate data keyed by raw IP (CT logs are indexed by hostname, not IP).

**What we *can* expose on the Workers runtime:**
- **Live session metadata** - `response.cf.tlsVersion` and `response.cf.tlsCipher` from the probe subrequest. Surfaced as `modules.tls.liveTls` whenever the runtime populates it.
- **CT-by-hostname** - `src/lib/providers/tls.ts` queries Certspotter (primary) and crt.sh (fallback) for the most recent leaf cert issued for the hostname. Filtered to skip shared multi-tenant certs that happen to include one SAN for the target.
- **CT-by-PTR for IP input** - when the user submits a bare IP, we use its reverse DNS (e.g. `1.1.1.1 -> one.one.one.one`) as the CT search key. It's not a live handshake, but in practice it surfaces the cert the origin actually serves.

**What would be needed for a true live cert probe:** either (a) a separate off-Workers service with raw TCP socket access that performs a real handshake and parses the X.509, or (b) a JS TLS 1.2/1.3 client + ASN.1 parser bundled into the Worker using `cloudflare:sockets`. Both are on the roadmap (Phase 4) but are not in the MVP.

### `whois` (registrar-level)
Classic `whois` uses TCP/43. Workers cannot reach it. RDAP (`https://rdap.org/domain/<d>`) is usable over HTTPS and may be added in a future phase, but it is not included in the MVP to avoid rate-limit surprises.

## Available but deliberately scoped

- **ASN lookups** use Team Cymru's DNS-based whois (`origin.asn.cymru.com`) via DoH. This works for IPv4 today; IPv6 ASN lookup via `origin6.asn.cymru.com` uses a different name format and is not wired up.
- **DKIM selector probe** cannot enumerate unknown selectors - by design, there is no way to "list" selectors for a domain. We probe a short built-in list (`default`, `google`, `selector1`, `selector2`, `k1`, `mail`). The user can pass custom selectors via the tool API.

## Why we disclose this

Every diagnostic tool has limits. Most sites pretend they don't. If a tool silently returns "no certificate found" when it just can't see one, the engineer will waste minutes (or hours) chasing a ghost. netrecon is built to tell the truth about what it does and doesn't know.
