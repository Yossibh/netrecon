import type { ShodanModuleResult } from '@/types';

// Shodan integration. Requires a paid API key bound as SHODAN_API_KEY.
//
// Endpoints used:
// - GET /shodan/host/{ip}?key=...          per-IP posture (ports, banners, vulns, tags)
// - GET /dns/domain/{domain}?key=...       subdomains + DNS records seen by Shodan
//
// Both are paid endpoints. A free Shodan account cannot call /shodan/host/{ip};
// it returns HTTP 401. We fail cleanly when the key is missing or the call is
// unauthorized, rather than pretending we have no data.
//
// Docs: https://developer.shodan.io/api

interface ShodanHostResponse {
  ip_str?: string;
  org?: string;
  isp?: string;
  asn?: string;
  os?: string | null;
  hostnames?: string[];
  domains?: string[];
  tags?: string[];
  ports?: number[];
  vulns?: string[];
  country_code?: string;
  city?: string;
  region_code?: string;
  last_update?: string;
  data?: Array<{
    port?: number;
    transport?: string;
    product?: string;
    version?: string;
    cpe?: string[];
    timestamp?: string;
    hostnames?: string[];
    ssl?: {
      cert?: { subject?: Record<string, string>; issuer?: Record<string, string>; expires?: string; issued?: string };
      versions?: string[];
    };
  }>;
}

interface ShodanDomainResponse {
  domain?: string;
  subdomains?: string[];
  tags?: string[];
  data?: Array<{ subdomain?: string; type?: string; value?: string; ports?: number[]; last_seen?: string }>;
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
  } finally {
    clearTimeout(timer);
  }
}

export async function shodanHost(ip: string, apiKey: string): Promise<ShodanModuleResult> {
  try {
    const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`;
    const res = await fetchWithTimeout(url, 10_000);
    if (res.status === 404) {
      return { ok: true, kind: 'host', ip, skipped: true, skipReason: 'Shodan has no records for this IP.' };
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: true, kind: 'host', ip, skipped: true, skipReason: 'Shodan API key rejected (paid membership required for /shodan/host).' };
    }
    if (!res.ok) {
      return { ok: true, kind: 'host', ip, skipped: true, skipReason: `Shodan returned HTTP ${res.status}` };
    }
    const body = (await res.json()) as ShodanHostResponse;
    const services = (body.data ?? []).map((s) => ({
      port: s.port,
      transport: s.transport,
      product: s.product,
      version: s.version,
      cpe: s.cpe ?? [],
      hostnames: s.hostnames ?? [],
      timestamp: s.timestamp,
      ssl: s.ssl?.cert
        ? {
            subjectCn: s.ssl.cert.subject?.CN,
            issuerCn: s.ssl.cert.issuer?.CN,
            notBefore: s.ssl.cert.issued,
            notAfter: s.ssl.cert.expires,
            versions: s.ssl.versions ?? [],
          }
        : undefined,
    }));
    return {
      ok: true,
      kind: 'host',
      ip,
      hostnames: body.hostnames ?? [],
      domains: body.domains ?? [],
      org: body.org,
      isp: body.isp,
      asn: body.asn,
      os: body.os ?? undefined,
      tags: body.tags ?? [],
      ports: body.ports ?? [],
      vulns: body.vulns ?? [],
      lastUpdate: body.last_update,
      services,
    };
  } catch (e) {
    return {
      ok: true,
      kind: 'host',
      ip,
      skipped: true,
      skipReason: e instanceof Error ? `Shodan error: ${e.message}` : 'Shodan error',
    };
  }
}

export async function shodanDomain(domain: string, apiKey: string): Promise<ShodanModuleResult> {
  try {
    const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiKey)}`;
    const res = await fetchWithTimeout(url, 10_000);
    if (res.status === 404) {
      return { ok: true, kind: 'domain', domain, skipped: true, skipReason: 'Shodan has no subdomain records for this domain.' };
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: true, kind: 'domain', domain, skipped: true, skipReason: 'Shodan API key rejected.' };
    }
    if (!res.ok) {
      return { ok: true, kind: 'domain', domain, skipped: true, skipReason: `Shodan returned HTTP ${res.status}` };
    }
    const body = (await res.json()) as ShodanDomainResponse;
    return {
      ok: true,
      kind: 'domain',
      domain,
      subdomains: body.subdomains ?? [],
      tags: body.tags ?? [],
      records: (body.data ?? []).map((r) => ({
        subdomain: r.subdomain,
        type: r.type,
        value: r.value,
        ports: r.ports ?? [],
        lastSeen: r.last_seen,
      })),
    };
  } catch (e) {
    return {
      ok: true,
      kind: 'domain',
      domain,
      skipped: true,
      skipReason: e instanceof Error ? `Shodan error: ${e.message}` : 'Shodan error',
    };
  }
}
