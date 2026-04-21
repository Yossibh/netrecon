import type { DnsModuleResult, HttpModuleResult, InferenceModuleResult } from '@/types';
import { lookupAsn, asnOwner } from './dns';

interface CdnSignature {
  name: string;
  headerMatchers: Array<{ header: string; pattern: RegExp }>;
  asnIds?: number[];
}

// NOTE: Cloudflare's `server: cloudflare` and `cf-ray` headers are stripped
// upstream in http.ts when they originate from our own Workers runtime. The
// remaining matcher would only fire if the origin genuinely re-exposes them.
// In practice, Cloudflare is most reliably detected via ASN (AS13335).
const CDN_SIGNATURES: CdnSignature[] = [
  {
    name: 'Cloudflare',
    headerMatchers: [
      { header: 'cf-ray', pattern: /./ },
    ],
    asnIds: [13335],
  },
  {
    name: 'Fastly',
    headerMatchers: [
      { header: 'x-served-by', pattern: /cache-/i },
      { header: 'x-fastly-request-id', pattern: /./ },
      { header: 'server', pattern: /fastly/i },
    ],
    asnIds: [54113],
  },
  {
    name: 'Akamai',
    headerMatchers: [
      { header: 'server', pattern: /AkamaiGHost|AkamaiNetStorage/i },
      { header: 'x-akamai-transformed', pattern: /./ },
      { header: 'x-akamai-request-id', pattern: /./ },
    ],
    asnIds: [20940, 16625, 21342, 12222, 16702, 17204, 18717, 23454, 23455, 32787, 33905, 35204],
  },
  {
    name: 'AWS CloudFront',
    headerMatchers: [
      { header: 'server', pattern: /CloudFront/i },
      { header: 'x-amz-cf-id', pattern: /./ },
    ],
    asnIds: [16509, 14618],
  },
  {
    name: 'Azure Front Door',
    headerMatchers: [
      { header: 'x-azure-ref', pattern: /./ },
      { header: 'x-cache', pattern: /azure/i },
      { header: 'x-msedge-ref', pattern: /./ },
    ],
    asnIds: [8075],
  },
  {
    name: 'Google Cloud CDN',
    headerMatchers: [
      { header: 'via', pattern: /google/i },
      { header: 'server', pattern: /^gws$|^GSE$/i },
    ],
    asnIds: [15169, 396982],
  },
  {
    name: 'Vercel',
    headerMatchers: [
      { header: 'server', pattern: /Vercel/i },
      { header: 'x-vercel-id', pattern: /./ },
    ],
  },
  {
    name: 'Netlify',
    headerMatchers: [{ header: 'server', pattern: /Netlify/i }],
  },
  {
    name: 'GitHub Pages',
    headerMatchers: [{ header: 'server', pattern: /GitHub\.com/i }],
  },
];

export async function inferInfrastructure(
  dns: DnsModuleResult | undefined,
  http: HttpModuleResult | undefined,
  directIp?: { ip: string; asn?: number; owner?: string; cc?: string; registry?: string }
): Promise<InferenceModuleResult> {
  const evidence: string[] = [];
  const proxyHints: string[] = [];
  let cdnName: string | undefined;

  const headers = http?.headers ?? {};
  if (headers['via']) proxyHints.push(`via: ${headers['via']}`);
  if (headers['x-cache']) proxyHints.push(`x-cache: ${headers['x-cache']}`);
  if (headers['x-forwarded-for']) proxyHints.push('x-forwarded-for present in response');

  for (const sig of CDN_SIGNATURES) {
    for (const m of sig.headerMatchers) {
      const val = headers[m.header];
      if (val && m.pattern.test(val)) {
        cdnName = sig.name;
        evidence.push(`Header ${m.header}: ${val} matches ${sig.name}`);
        break;
      }
    }
    if (cdnName === sig.name) break;
  }

  // ASN: prefer directIp (IP input) else first A record
  let asnInfo: InferenceModuleResult['asn'];
  const firstA = dns?.records.A[0]?.data;
  const targetIp = directIp?.ip ?? firstA;
  if (directIp?.asn) {
    asnInfo = { ip: directIp.ip, asn: directIp.asn, owner: directIp.owner, cc: directIp.cc, registry: directIp.registry };
    evidence.push(`${directIp.ip} -> AS${directIp.asn}${directIp.owner ? ` (${directIp.owner})` : ''}`);
  } else if (targetIp) {
    try {
      const asn = await lookupAsn(targetIp);
      if (asn?.asn) {
        const owner = await asnOwner(asn.asn).catch(() => undefined);
        asnInfo = { ip: targetIp, asn: asn.asn, owner, cc: asn.cc, registry: asn.registry };
        evidence.push(`${targetIp} -> AS${asn.asn}${owner ? ` (${owner})` : ''}`);
      }
    } catch {
      /* ignore */
    }
  }

  if (!cdnName && asnInfo?.asn) {
    for (const sig of CDN_SIGNATURES) {
      if (sig.asnIds?.includes(asnInfo.asn)) {
        cdnName = sig.name;
        evidence.push(`ASN ${asnInfo.asn} belongs to ${sig.name}`);
        break;
      }
    }
  }

  // Origin-exposure correlation:
  // If HTTP headers claim a CDN but the A record ASN does NOT match that CDN,
  // the origin may be directly exposed.
  let originExposureRisk: InferenceModuleResult['originExposureRisk'];
  if (cdnName && asnInfo?.asn) {
    const sig = CDN_SIGNATURES.find((s) => s.name === cdnName);
    if (sig?.asnIds?.length && !sig.asnIds.includes(asnInfo.asn)) {
      originExposureRisk = {
        risk: 'medium',
        reason: `${cdnName} signals in headers but A record (AS${asnInfo.asn}${asnInfo.owner ? ` ${asnInfo.owner}` : ''}) is not in ${cdnName}'s ASN set. Origin may be directly reachable.`,
      };
    } else {
      originExposureRisk = { risk: 'low', reason: `A record ASN matches ${cdnName}.` };
    }
  } else if (cdnName && !asnInfo) {
    originExposureRisk = { risk: 'none', reason: 'CDN detected via headers; ASN lookup unavailable for correlation.' };
  }

  return {
    ok: true,
    cdn: cdnName ? { detected: true, name: cdnName, evidence } : { detected: false, evidence },
    proxyHints,
    asn: asnInfo,
    originExposureRisk,
  };
}
