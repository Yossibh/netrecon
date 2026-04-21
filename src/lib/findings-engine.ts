import type { AnalyzeModules, Finding, NormalizedInput } from '@/types';

type Rule = (ctx: { input: NormalizedInput; modules: AnalyzeModules }) => Finding[];

function f(
  id: string,
  severity: Finding['severity'],
  title: string,
  explanation: string,
  evidence: string[] = [],
  nextSteps: string[] = [],
  suggestedCommands: string[] = [],
  module?: string
): Finding {
  return { id, severity, title, explanation, evidence, nextSteps, suggestedCommands, module };
}

// DNS rules --------------------------------------------------------------------
const dnsRules: Rule[] = [
  ({ modules, input }) => {
    const d = modules.dns;
    if (!d?.ok || !input.domain) return [];
    if (d.records.A.length === 0 && d.records.AAAA.length === 0 && d.records.CNAME.length === 0) {
      return [
        f(
          'dns.no-address-records',
          'high',
          'Domain does not resolve to any address',
          'No A, AAAA, or CNAME records were returned. The domain cannot be reached over HTTP(S).',
          ['A: []', 'AAAA: []', 'CNAME: []'],
          ['Verify the domain is registered and nameservers are delegated correctly.', 'Check the registrar for nameserver configuration.'],
          [`dig NS ${input.domain} +short`, `whois ${input.domain}`],
          'dns'
        ),
      ];
    }
    return [];
  },
  ({ modules, input }) => {
    const d = modules.dns;
    if (!d?.ok || !input.domain) return [];
    if (!d.hasIPv6 && d.records.A.length > 0) {
      return [
        f(
          'dns.missing-ipv6',
          'info',
          'No IPv6 (AAAA) records',
          'The domain is IPv4-only. Adding AAAA records improves reachability for IPv6-only clients and networks that prefer IPv6.',
          ['AAAA: []'],
          ['Publish AAAA records for the primary hostname.'],
          [`dig AAAA ${input.domain} +short`],
          'dns'
        ),
      ];
    }
    return [];
  },
  ({ modules, input }) => {
    const d = modules.dns;
    if (!d?.ok || !input.domain) return [];
    if (!d.hasCAA) {
      return [
        f(
          'dns.missing-caa',
          'low',
          'No CAA records',
          'CAA records restrict which CAs may issue certificates for this domain. Without CAA, any CA may issue a certificate.',
          ['CAA: []'],
          ['Publish CAA records pinning your issuer(s).'],
          [`dig CAA ${input.domain} +short`],
          'dns'
        ),
      ];
    }
    return [];
  },
  ({ modules, input }) => {
    const d = modules.dns;
    if (!d?.ok || !input.domain) return [];
    if (d.dnssec === false) {
      return [
        f(
          'dns.dnssec-unverified',
          'info',
          'DNSSEC not validated',
          'The DoH resolver did not flag this response as DNSSEC-authenticated (AD=0).',
          [`AD bit: ${d.dnssec}`],
          ['If you operate this zone, consider signing it and publishing DS records at the parent.'],
          [`dig DNSKEY ${input.domain} +dnssec`],
          'dns'
        ),
      ];
    }
    return [];
  },
];

// Email rules ------------------------------------------------------------------
const emailRules: Rule[] = [
  ({ modules, input }) => {
    const e = modules.email;
    if (!e?.ok || !input.domain) return [];
    const out: Finding[] = [];
    if (e.mxPresent && !e.spf?.present) {
      out.push(
        f(
          'email.no-spf',
          'medium',
          'Missing SPF record',
          'Domain has MX records but no SPF policy. Receiving mail servers cannot verify the sender IP; spoofing is easier.',
          ['No TXT record beginning with v=spf1'],
          ['Publish an SPF TXT record such as "v=spf1 include:_spf.example.com -all".'],
          [`dig TXT ${input.domain} +short`],
          'email'
        )
      );
    }
    if (!e.dmarc?.present) {
      out.push(
        f(
          'email.no-dmarc',
          'medium',
          'Missing DMARC record',
          'No DMARC policy is published. Receivers cannot enforce or report on SPF/DKIM alignment. Spoofing risk is elevated.',
          [`Queried: _dmarc.${input.domain}`],
          ['Publish a DMARC record starting with "v=DMARC1; p=none;" for monitoring, then tighten to quarantine/reject.'],
          [`dig TXT _dmarc.${input.domain} +short`],
          'email'
        )
      );
    } else if (e.dmarc.policy === 'none') {
      out.push(
        f(
          'email.dmarc-p-none',
          'low',
          'DMARC policy is p=none',
          'DMARC is published but set to monitor-only. Receivers will not reject or quarantine unaligned mail.',
          [e.dmarc.raw ?? ''],
          ['Once reports confirm legitimate senders are aligned, move to p=quarantine and then p=reject.'],
          [`dig TXT _dmarc.${input.domain} +short`],
          'email'
        )
      );
    }
    if (e.spf?.present && e.spf.qualifier && ['+', '?'].includes(e.spf.qualifier)) {
      out.push(
        f(
          'email.spf-weak-qualifier',
          'low',
          `SPF uses permissive "${e.spf.qualifier}all" terminal`,
          'A permissive SPF terminal mechanism weakens anti-spoofing. Prefer "-all" (hard fail) or at least "~all" (soft fail).',
          [e.spf.raw ?? ''],
          ['Tighten the SPF record to end with "-all" after verifying all legitimate senders are included.'],
          [],
          'email'
        )
      );
    }
    return out;
  },
];

// HTTP rules -------------------------------------------------------------------
const httpRules: Rule[] = [
  ({ modules }) => {
    const h = modules.http;
    if (!h?.ok) return [];
    if (!h.securityHeaders.hsts) {
      return [
        f(
          'http.no-hsts',
          'low',
          'No HSTS header',
          'Strict-Transport-Security was not set. Browsers will not enforce HTTPS on subsequent visits; downgrade attacks become easier.',
          [`final URL: ${h.finalUrl}`],
          ['Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" on HTTPS responses.'],
          [],
          'http'
        ),
      ];
    }
    return [];
  },
  ({ modules }) => {
    const h = modules.http;
    if (!h?.ok) return [];
    const out: Finding[] = [];
    if (h.corsHeaders.accessControlAllowOrigin === '*' &&
        (h.corsHeaders.accessControlAllowCredentials?.toLowerCase() === 'true')) {
      out.push(
        f(
          'http.cors-wildcard-with-credentials',
          'high',
          'CORS wildcard with credentials',
          'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is invalid per spec and can indicate a misconfigured origin.',
          [`ACAO: *`, `ACAC: true`],
          ['Replace "*" with an explicit allowlist of origins when credentials are allowed.'],
          [],
          'http'
        )
      );
    } else if (h.corsHeaders.accessControlAllowOrigin === '*') {
      out.push(
        f(
          'http.cors-wildcard',
          'info',
          'CORS wildcard origin',
          'Access-Control-Allow-Origin is "*". This is fine for public APIs but exposes any authenticated endpoint to cross-origin access.',
          [`ACAO: *`],
          ['Confirm no authenticated or privileged response paths reuse this header.'],
          [],
          'http'
        )
      );
    }
    return out;
  },
  ({ modules }) => {
    const h = modules.http;
    if (!h?.ok) return [];
    if (h.redirects.length >= 4) {
      return [
        f(
          'http.long-redirect-chain',
          'low',
          `Redirect chain of ${h.redirects.length} hops`,
          'Long redirect chains increase latency and can mask misconfiguration (HTTP↔HTTPS, www↔apex ping-pong, etc.).',
          h.redirects.map((r) => `${r.status} ${r.from} -> ${r.to}`),
          ['Collapse intermediate hops to a single final destination.'],
          [],
          'http'
        ),
      ];
    }
    return [];
  },
  ({ modules }) => {
    const h = modules.http;
    if (h && !h.ok && h.error?.includes('Redirect loop')) {
      return [
        f(
          'http.redirect-loop',
          'high',
          'Redirect loop detected',
          h.error,
          h.redirects.map((r) => `${r.status} ${r.from} -> ${r.to}`),
          ['Inspect the server configuration causing the cycle (often HTTP/HTTPS or canonical host rules).'],
          [],
          'http'
        ),
      ];
    }
    return [];
  },
];

// TLS rules --------------------------------------------------------------------
const tlsRules: Rule[] = [
  ({ modules, input }) => {
    // Info-level disclosure for IP input: explain why we don't show a live
    // peer cert. Prevents users from thinking we're hiding data.
    if (input.type !== 'ip') return [];
    const t = modules.tls;
    if (!t) return [];
    const evidence: string[] = [];
    if (t.liveTls?.version) evidence.push(`Negotiated: ${t.liveTls.version}${t.liveTls.cipher ? ' ' + t.liveTls.cipher : ''}`);
    if (t.hostSearched) evidence.push(`CT searched by PTR hostname: ${t.hostSearched}`);
    return [
      f(
        'tls.ip-input-no-live-cert',
        'info',
        'TLS peer certificate not directly fetched',
        'Cloudflare Workers does not expose peer certificate details from fetch(). For IP input we surface the live session version/cipher the runtime negotiated, and - when reverse DNS resolves - search CT logs by the PTR hostname. This is not a live handshake.',
        evidence,
        ['Run the live openssl command below from a machine with raw socket access to confirm the actual served certificate.'],
        [`openssl s_client -connect ${input.ip}:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates -ext subjectAltName`],
        'tls'
      ),
    ];
  },
  ({ modules, input }) => {
    const t = modules.tls;
    if (!t?.ok || !t.latestCertificate || !input.domain) return [];
    const d = t.latestCertificate.daysUntilExpiry;
    if (d < 0) {
      return [
        f(
          'tls.certificate-expired',
          'high',
          `Latest certificate in CT logs is expired (${Math.abs(d)} days ago)`,
          'The most recent certificate issued for this domain (from crt.sh) is past its notAfter date. Note this reflects CT issuance, not a live handshake.',
          [`notAfter: ${t.latestCertificate.notAfter}`],
          ['Renew the certificate and verify the live chain with openssl s_client.'],
          [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -dates`],
          'tls'
        ),
      ];
    }
    if (d <= 14) {
      return [
        f(
          'tls.certificate-expiring-soon',
          'medium',
          `Latest certificate expires in ${d} days`,
          'The most recent CT log entry shows an imminent expiry. Confirm automation is renewing it.',
          [`notAfter: ${t.latestCertificate.notAfter}`],
          ['Verify ACME / renewal automation is running.', 'Check the live cert to confirm it matches what CT shows.'],
          [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -dates`],
          'tls'
        ),
      ];
    }
    return [];
  },
];

// Inference rules --------------------------------------------------------------
const inferenceRules: Rule[] = [
  ({ modules }) => {
    const i = modules.inference;
    if (!i?.ok || !i.originExposureRisk || i.originExposureRisk.risk === 'none' || i.originExposureRisk.risk === 'low') return [];
    return [
      f(
        'inference.origin-possibly-exposed',
        i.originExposureRisk.risk === 'high' ? 'high' : 'medium',
        'CDN in use but origin may be directly reachable',
        i.originExposureRisk.reason,
        i.cdn?.evidence ?? [],
        ['Verify origin firewall accepts connections only from the CDN\'s IP ranges.', 'Rotate the origin hostname / IP if it has leaked.'],
        [],
        'inference'
      ),
    ];
  },
];

const ipRules: Rule[] = [
  ({ modules }) => {
    const ip = modules.ip;
    if (!ip?.ok) return [];
    const out: Finding[] = [];
    if (ip.scope === 'private' || ip.scope === 'loopback' || ip.scope === 'link-local' || ip.scope === 'cgnat') {
      out.push(
        f(
          `ip.non-routable-${ip.scope}`,
          'medium',
          `Non-public address (${ip.scope})`,
          `This address is in a ${ip.scope} range and is not reachable from the public internet. External diagnostics (ASN, geo, PTR) have been skipped.`,
          ip.notes,
          [
            'Confirm whether you meant to share a public IP.',
            'If this IP is exposed on a router/NAT boundary, use the public egress IP instead.',
          ],
          [`ip a | grep ${ip.ip}`, `traceroute ${ip.ip}`],
          'ip'
        )
      );
    }
    if (ip.scope === 'documentation' || ip.scope === 'reserved' || ip.scope === 'benchmark' || ip.scope === 'unspecified' || ip.scope === 'multicast') {
      out.push(
        f(
          `ip.special-use-${ip.scope}`,
          'low',
          `Special-use address (${ip.scope})`,
          'This address is reserved by IANA and should not appear in production routing.',
          ip.notes,
          ['Double-check whether a real address was intended here.'],
          [],
          'ip'
        )
      );
    }
    if (ip.scope === 'public' && ip.ptr.length === 0) {
      out.push(
        f(
          'ip.missing-ptr',
          'info',
          'No reverse DNS (PTR) record',
          'The address has no PTR record. PTR is optional but helpful for mail reputation, traceroute readability, and operational debugging.',
          [],
          ['If this IP hosts outbound mail, publish a matching PTR and forward A record.'],
          [`dig -x ${ip.ip} +short`],
          'ip'
        )
      );
    }
    if (ip.anycast?.likely) {
      out.push(
        f(
          'ip.anycast-known',
          'info',
          'Known anycast address',
          ip.anycast.reason + '. Measurements from different vantage points will hit different backend PoPs.',
          [],
          ['When comparing behaviour across regions, treat this IP as a logical endpoint, not a single host.'],
          [],
          'ip'
        )
      );
    }
    return out;
  },
];

const shodanRules: Rule[] = [
  ({ modules }) => {
    const s = modules.shodan;
    if (!s || !s.ok || s.skipped || s.kind !== 'host') return [];
    const out: Finding[] = [];
    if (s.vulns && s.vulns.length) {
      out.push(
        f(
          'shodan.vulns',
          'high',
          `Shodan reports ${s.vulns.length} known CVE${s.vulns.length === 1 ? '' : 's'} on this host`,
          'Shodan correlates banner/version fingerprints against CVE databases. These are heuristics and may include false positives, but each warrants investigation.',
          s.vulns.slice(0, 15),
          ['Validate the reported CVEs against the actual installed versions.', 'Patch or mitigate confirmed vulnerabilities.'],
          [`shodan host ${s.ip}`, `curl -s 'https://api.shodan.io/shodan/host/${s.ip}?key=$SHODAN_API_KEY' | jq '.vulns'`],
          'shodan'
        )
      );
    }
    if (s.ports && s.ports.length) {
      const risky = s.ports.filter((p) => [21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017].includes(p));
      if (risky.length) {
        out.push(
          f(
            'shodan.risky-open-ports',
            'medium',
            `Potentially sensitive services exposed: ${risky.join(', ')}`,
            'Shodan observed these administrative/database/remote-access ports open to the public internet. Confirm intent and apply access controls.',
            [`Ports seen: ${s.ports.join(', ')}`],
            ['Restrict access via firewall / security group.', 'Put sensitive services behind a VPN or bastion.'],
            [`nmap -p ${risky.join(',')} ${s.ip}`],
            'shodan'
          )
        );
      }
    }
    return out;
  },
];

const ALL_RULES: Rule[] = [...dnsRules, ...emailRules, ...httpRules, ...tlsRules, ...inferenceRules, ...ipRules, ...shodanRules];

export function runFindings(ctx: { input: NormalizedInput; modules: AnalyzeModules }): Finding[] {
  const findings: Finding[] = [];
  for (const rule of ALL_RULES) {
    try {
      findings.push(...rule(ctx));
    } catch (e) {
      findings.push(
        f(
          'engine.rule-error',
          'info',
          'A findings rule failed to evaluate',
          e instanceof Error ? e.message : String(e),
          [],
          [],
          [],
          'engine'
        )
      );
    }
  }
  return findings;
}

export function riskLevel(findings: Finding[]): 'low' | 'medium' | 'high' {
  if (findings.some((f) => f.severity === 'high')) return 'high';
  if (findings.some((f) => f.severity === 'medium')) return 'medium';
  return 'low';
}
