import type { TlsModuleResult } from '@/types';

// TLS inspection strategy:
//
// Cloudflare Workers cannot perform a raw TLS handshake against the origin and
// thus cannot read the peer certificate directly. To produce useful TLS output
// we combine two independent sources:
//
// 1. Certificate issuance / expiry (primary: Certspotter, fallback: crt.sh)
//    Certspotter is more reliable than crt.sh and has a clean JSON API with a
//    generous unauthenticated rate limit. API docs: https://sslmate.com/ct_search_api/
//    TODO: add an optional SSLMATE_API_KEY env binding to raise the rate limit.
//
// 2. Live TLS metadata from the HTTP probe response (passed in via opts).
//    When we fetch the target URL, Cloudflare exposes response.cf.tlsVersion
//    and response.cf.tlsCipher. Those are the session version/cipher used on
//    the subrequest. This is live, origin-specific truth (no third party).
//
// If both sources fail we surface a clear, actionable reason rather than a
// cryptic error string.

interface CertspotterIssuance {
  id: string;
  tbs_sha256: string;
  dns_names: string[];
  pubkey_sha256: string;
  issuer?: { name?: string; pubkey_sha256?: string };
  not_before: string;
  not_after: string;
}

interface CrtShEntry {
  issuer_name: string;
  common_name?: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

async function fetchWithTimeout(url: string, ms: number, init?: RequestInit): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function queryCertspotter(domain: string): Promise<TlsModuleResult | null> {
  // include_subdomains + match_wildcards ensures we find certs issued at the
  // apex or via wildcards when the user enters a subdomain like www.example.com.
  const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer`;
  try {
    const res = await fetchWithTimeout(url, 10_000, { headers: { accept: 'application/json' } });
    if (res.status === 429) return { ok: true, source: 'unavailable', skipped: true, skipReason: 'Certspotter rate limit hit. Try again later or set SSLMATE_API_KEY.' };
    if (!res.ok) return null;
    const entries = (await res.json()) as CertspotterIssuance[];
    if (!entries.length) return { ok: true, source: 'certspotter', recentCount: 0 };
    entries.sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime());
    const latest = entries[0]!;
    const daysUntilExpiry = Math.floor((new Date(latest.not_after).getTime() - Date.now()) / 86_400_000);
    return {
      ok: true,
      source: 'certspotter',
      recentCount: entries.length,
      latestCertificate: {
        issuer: latest.issuer?.name ?? 'unknown',
        notBefore: latest.not_before,
        notAfter: latest.not_after,
        daysUntilExpiry,
        commonName: latest.dns_names[0],
        sans: Array.from(new Set(latest.dns_names)),
      },
    };
  } catch {
    return null;
  }
}

async function queryCrtSh(domain: string): Promise<TlsModuleResult | null> {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired`;
  try {
    const res = await fetchWithTimeout(url, 15_000, { headers: { accept: 'application/json' } });
    if (!res.ok) return null;
    const text = await res.text();
    if (!text.trim()) return { ok: true, source: 'crt.sh', recentCount: 0 };
    let entries: CrtShEntry[];
    try { entries = JSON.parse(text); } catch { return null; }
    if (!entries.length) return { ok: true, source: 'crt.sh', recentCount: 0 };
    entries.sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime());
    const latest = entries[0]!;
    const daysUntilExpiry = Math.floor((new Date(latest.not_after).getTime() - Date.now()) / 86_400_000);
    const sans = Array.from(new Set((latest.name_value || '').split('\n').map((s) => s.trim()).filter(Boolean)));
    return {
      ok: true,
      source: 'crt.sh',
      recentCount: entries.length,
      latestCertificate: {
        issuer: latest.issuer_name,
        notBefore: latest.not_before,
        notAfter: latest.not_after,
        daysUntilExpiry,
        commonName: latest.common_name,
        sans,
      },
    };
  } catch {
    return null;
  }
}

export interface InspectTlsOpts {
  /** live TLS metadata from the HTTP probe's response.cf (Workers-only) */
  live?: { version?: string; cipher?: string };
}

export async function inspectTls(domain: string, opts: InspectTlsOpts = {}): Promise<TlsModuleResult> {
  // Normalize: strip leading www. We always query the broader scope because
  // Certspotter/crt.sh index by issued SAN, and many sites only have certs
  // issued at the apex or via wildcards rather than per-subdomain.
  const stripped = domain.replace(/^www\./i, '');
  const targets = stripped === domain ? [domain] : [domain, stripped];

  let result: TlsModuleResult | null = null;
  for (const t of targets) {
    const [certspotter, crtsh] = await Promise.all([queryCertspotter(t), queryCrtSh(t)]);
    const candidate = certspotter ?? crtsh;
    if (candidate && candidate.source !== 'unavailable' && (candidate.recentCount ?? 0) > 0) {
      result = candidate;
      break;
    }
    // keep last non-null as a fallback so we still report "0 certificates" rather than null
    if (!result && candidate) result = candidate;
  }

  result = result ?? {
    ok: true as const,
    source: 'unavailable' as const,
    skipped: true as const,
    skipReason: 'Both Certspotter and crt.sh were unreachable. Certificate inspection is best-effort on the Cloudflare MVP; see /docs/limitations.md.',
  };
  if (opts.live && (opts.live.version || opts.live.cipher)) {
    result.liveTls = { version: opts.live.version, cipher: opts.live.cipher };
  }
  return result;
}
