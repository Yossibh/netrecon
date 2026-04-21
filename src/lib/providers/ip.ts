import type { IpModuleResult } from '@/types';
import { lookupAsn, asnOwner } from './dns';

// Well-known anycast addresses used by public DNS / resolvers / root-adjacent
// infra. Presence here is informational - it's a hint, not ground truth.
const KNOWN_ANYCAST: Record<string, string> = {
  '1.1.1.1': 'Cloudflare 1.1.1.1 public DNS (anycast)',
  '1.0.0.1': 'Cloudflare 1.0.0.1 public DNS (anycast)',
  '8.8.8.8': 'Google Public DNS (anycast)',
  '8.8.4.4': 'Google Public DNS (anycast)',
  '9.9.9.9': 'Quad9 public DNS (anycast)',
  '149.112.112.112': 'Quad9 public DNS (anycast)',
  '208.67.222.222': 'OpenDNS (anycast)',
  '208.67.220.220': 'OpenDNS (anycast)',
  '94.140.14.14': 'AdGuard DNS (anycast)',
  '76.76.2.0': 'Control D DNS (anycast)',
  '2606:4700:4700::1111': 'Cloudflare 1.1.1.1 public DNS (anycast)',
  '2606:4700:4700::1001': 'Cloudflare 1.0.0.1 public DNS (anycast)',
  '2001:4860:4860::8888': 'Google Public DNS (anycast)',
  '2001:4860:4860::8844': 'Google Public DNS (anycast)',
  '2620:fe::fe': 'Quad9 public DNS (anycast)',
};

interface IpWhoIs {
  success?: boolean;
  ip?: string;
  type?: string;
  continent?: string;
  continent_code?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: { id?: string; utc?: string };
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };
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

// Classify an address by scope. Returns public/private/special-use categories
// per RFC 1918, RFC 4193, RFC 6598 (CGNAT), RFC 5737 (documentation), etc.
function classify(ip: string, version: 'v4' | 'v6'): {
  scope:
    | 'public'
    | 'private'
    | 'loopback'
    | 'link-local'
    | 'cgnat'
    | 'multicast'
    | 'reserved'
    | 'documentation'
    | 'unspecified'
    | 'benchmark';
  notes: string[];
} {
  const notes: string[] = [];
  if (version === 'v4') {
    const parts = ip.split('.').map((n) => parseInt(n, 10));
    const [a = 0, b = 0] = parts;
    if (a === 0) return { scope: 'unspecified', notes: ['0.0.0.0/8 - "this" network (RFC 1122)'] };
    if (a === 10) return { scope: 'private', notes: ['10.0.0.0/8 (RFC 1918 private)'] };
    if (a === 127) return { scope: 'loopback', notes: ['127.0.0.0/8 loopback (RFC 1122)'] };
    if (a === 169 && b === 254) return { scope: 'link-local', notes: ['169.254.0.0/16 link-local (RFC 3927)'] };
    if (a === 172 && b >= 16 && b <= 31) return { scope: 'private', notes: ['172.16.0.0/12 (RFC 1918 private)'] };
    if (a === 192 && b === 168) return { scope: 'private', notes: ['192.168.0.0/16 (RFC 1918 private)'] };
    if (a === 100 && b >= 64 && b <= 127) return { scope: 'cgnat', notes: ['100.64.0.0/10 CGNAT (RFC 6598)'] };
    if (a === 192 && b === 0 && parts[2] === 2) return { scope: 'documentation', notes: ['192.0.2.0/24 TEST-NET-1 (RFC 5737)'] };
    if (a === 198 && parts[2] === 51 && parts[3] === 100) return { scope: 'documentation', notes: ['198.51.100.0/24 TEST-NET-2 (RFC 5737)'] };
    if (a === 203 && parts[2] === 0 && parts[3] === 113) return { scope: 'documentation', notes: ['203.0.113.0/24 TEST-NET-3 (RFC 5737)'] };
    if (a === 198 && b >= 18 && b <= 19) return { scope: 'benchmark', notes: ['198.18.0.0/15 benchmark (RFC 2544)'] };
    if (a >= 224 && a <= 239) return { scope: 'multicast', notes: ['224.0.0.0/4 multicast (RFC 5771)'] };
    if (a >= 240) return { scope: 'reserved', notes: ['240.0.0.0/4 reserved for future use (RFC 1112)'] };
    return { scope: 'public', notes };
  }
  // v6
  const ipl = ip.toLowerCase();
  if (ipl === '::' || ipl === '0:0:0:0:0:0:0:0') return { scope: 'unspecified', notes: ['::/128 unspecified'] };
  if (ipl === '::1' || ipl === '0:0:0:0:0:0:0:1') return { scope: 'loopback', notes: ['::1/128 loopback'] };
  if (/^fe[89ab]/.test(ipl)) return { scope: 'link-local', notes: ['fe80::/10 link-local (RFC 4291)'] };
  if (/^f[cd]/.test(ipl)) return { scope: 'private', notes: ['fc00::/7 unique local address (RFC 4193)'] };
  if (/^ff/.test(ipl)) return { scope: 'multicast', notes: ['ff00::/8 multicast (RFC 4291)'] };
  if (/^2001:db8:/.test(ipl)) return { scope: 'documentation', notes: ['2001:db8::/32 documentation (RFC 3849)'] };
  return { scope: 'public', notes };
}

function ptrQueryName(ip: string, version: 'v4' | 'v6'): string {
  if (version === 'v4') {
    return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  }
  // Expand IPv6 to 32 hex nibbles
  const parts = ip.toLowerCase().split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length > 1 ? parts[1]!.split(':').filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  const full = [
    ...left.map((g) => g.padStart(4, '0')),
    ...Array(missing).fill('0000'),
    ...right.map((g) => g.padStart(4, '0')),
  ].join('');
  return full.split('').reverse().join('.') + '.ip6.arpa';
}

async function reverseDns(ip: string, version: 'v4' | 'v6'): Promise<string[]> {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(ptrQueryName(ip, version))}&type=PTR`;
    const r = await fetchWithTimeout(url, 5_000, { headers: { accept: 'application/dns-json' } });
    if (!r.ok) return [];
    const body = (await r.json()) as { Answer?: { type: number; data: string }[] };
    return (body.Answer ?? []).filter((a) => a.type === 12).map((a) => a.data.replace(/\.$/, ''));
  } catch {
    return [];
  }
}

async function geolocate(ip: string): Promise<IpWhoIs | null> {
  try {
    // ipwho.is: free, no auth, generous limits, returns geo + ASN in one call.
    // TODO: add optional IPINFO_TOKEN / MAXMIND_LICENSE_KEY for higher-fidelity data.
    const res = await fetchWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`, 6_000, {
      headers: { accept: 'application/json' },
    });
    if (!res.ok) return null;
    const body = (await res.json()) as IpWhoIs;
    if (body.success === false) return null;
    return body;
  } catch {
    return null;
  }
}

export async function analyzeIp(ip: string, version: 'v4' | 'v6'): Promise<IpModuleResult> {
  const { scope, notes } = classify(ip, version);

  // Short-circuit non-public addresses: we can still return classification
  // but skip external lookups that would be meaningless / reveal nothing.
  if (scope !== 'public') {
    return {
      ok: true,
      ip,
      version,
      scope,
      notes,
      anycast: KNOWN_ANYCAST[ip] ? { likely: true, reason: KNOWN_ANYCAST[ip]! } : undefined,
      ptr: [],
      geo: null,
      asn: null,
    };
  }

  const [ptr, geo, asn] = await Promise.all([
    reverseDns(ip, version),
    geolocate(ip),
    lookupAsn(ip).catch(() => null),
  ]);

  let asnInfo: IpModuleResult['asn'] = null;
  if (asn?.asn) {
    const owner = await asnOwner(asn.asn).catch(() => undefined);
    asnInfo = { asn: asn.asn, owner, cc: asn.cc, registry: asn.registry };
  } else if (geo?.connection?.asn) {
    asnInfo = { asn: geo.connection.asn, owner: geo.connection.org || geo.connection.isp, cc: geo?.country_code };
  }

  const anycastKnown = KNOWN_ANYCAST[ip];

  return {
    ok: true,
    ip,
    version,
    scope,
    notes,
    anycast: anycastKnown ? { likely: true, reason: anycastKnown } : undefined,
    ptr,
    geo: geo
      ? {
          country: geo.country,
          countryCode: geo.country_code,
          region: geo.region,
          city: geo.city,
          latitude: geo.latitude,
          longitude: geo.longitude,
          timezone: geo.timezone?.id,
          org: geo.connection?.org,
          isp: geo.connection?.isp,
        }
      : null,
    asn: asnInfo,
  };
}
