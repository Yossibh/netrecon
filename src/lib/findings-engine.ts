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

const exposureRules: Rule[] = [
  ({ modules }) => {
    const s = modules.exposure;
    if (!s || !s.ok || s.skipped || s.kind !== 'host') return [];
    const out: Finding[] = [];
    if (s.vulns && s.vulns.length) {
      out.push(
        f(
          'exposure.vulns',
          'high',
          `${s.vulns.length} known CVE${s.vulns.length === 1 ? '' : 's'} reported on this host`,
          'The host\'s exposed banners and versions match entries in public CVE databases. These are heuristics and may include false positives, but each warrants investigation.',
          s.vulns.slice(0, 15),
          ['Validate the reported CVEs against the actual installed versions.', 'Patch or mitigate confirmed vulnerabilities.'],
          [],
          'exposure'
        )
      );
    }
    if (s.ports && s.ports.length) {
      const risky = s.ports.filter((p) => [21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017].includes(p));
      if (risky.length) {
        out.push(
          f(
            'exposure.risky-open-ports',
            'medium',
            `Potentially sensitive services exposed: ${risky.join(', ')}`,
            'These administrative/database/remote-access ports were observed open to the public internet. Confirm intent and apply access controls.',
            [`Ports seen: ${s.ports.join(', ')}`],
            ['Restrict access via firewall / security group.', 'Put sensitive services behind a VPN or bastion.'],
            [`nmap -p ${risky.join(',')} ${s.ip}`],
            'exposure'
          )
        );
      }
    }
    return out;
  },
];

// Live peer TLS rules ----------------------------------------------------------
const livetlsRules: Rule[] = [
  ({ modules, input }) => {
    const lt = modules.livetls;
    if (!lt?.ok || !lt.certs?.[0] || !input.domain) return [];
    const c = lt.certs[0];
    const out: Finding[] = [];
    if (c.expired) {
      out.push(f(
        'livetls.peer-expired',
        'high',
        'Peer is serving an expired certificate',
        'A live TLS handshake returned a certificate whose notAfter is in the past. Monitoring that relies on CT logs alone will miss this — CT shows certs that were issued, not what is currently deployed.',
        [`notAfter: ${c.notAfter}`, `source: ${lt.source ?? 'unknown'}`, `subject: ${c.subject}`],
        ['Deploy the renewed certificate to the origin.', 'Verify your renewal automation (ACME / cert-manager) is running.'],
        [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -dates`],
        'livetls',
      ));
    } else if (c.daysUntilExpiry >= 0 && c.daysUntilExpiry < 14) {
      out.push(f(
        'livetls.peer-expiring-soon',
        'medium',
        `Peer certificate expires in ${c.daysUntilExpiry} day(s)`,
        'The cert actually being served is close to expiry. This is the authoritative signal, not CT logs.',
        [`notAfter: ${c.notAfter}`, `source: ${lt.source ?? 'unknown'}`],
        ['Confirm renewal automation is queued to run before the expiry date.'],
        [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -dates`],
        'livetls',
      ));
    }
    if (lt.hostnameMatch === false) {
      out.push(f(
        'livetls.hostname-mismatch',
        'high',
        'Peer certificate SANs do not match the requested hostname',
        'The certificate served at this hostname is not valid for it. Browsers will show a NET::ERR_CERT_COMMON_NAME_INVALID error.',
        [`subject: ${c.subject}`, `SANs: ${c.sans.join(', ') || '(none)'}`],
        ['Check origin routing / SNI configuration on the load balancer.', 'Confirm the correct cert is bound to this hostname.'],
        [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -subject -ext subjectAltName`],
        'livetls',
      ));
    }
    if (c.selfSigned) {
      out.push(f(
        'livetls.self-signed',
        'high',
        'Peer is serving a self-signed certificate',
        'Browsers and most clients will reject this connection. Self-signed certs are acceptable for local testing only.',
        [`subject: ${c.subject}`, `issuer: ${c.issuer || '(empty)'}`],
        ['Deploy a certificate from a publicly trusted CA (Let\'s Encrypt, Google Trust Services, etc.).'],
        [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -issuer -subject`],
        'livetls',
      ));
    }
    return out;
  },
  // Cross-check: CT vs peer cert.
  ({ modules, input }) => {
    const lt = modules.livetls;
    const ct = modules.tls;
    if (!lt?.ok || !lt.certs?.[0] || !ct?.latestCertificate || !input.domain) return [];
    const peer = lt.certs[0];
    const ctCert = ct.latestCertificate;
    // Compare notAfter. Newer issuance in CT that isn't yet deployed is normal
    // (CT sees issuance instantly, deployment may lag by minutes to hours).
    // Only flag if the peer is actively expired while CT shows something newer.
    if (peer.expired && new Date(ctCert.notAfter).getTime() > Date.now()) {
      return [
        f(
          'livetls.ct-drift-peer-expired',
          'high',
          'CT logs show a valid cert but peer is still serving an expired one',
          'A newer certificate has been issued (visible in Certificate Transparency) and is still valid, but the origin is serving an older, expired cert. This is classic deployment drift: issuance succeeded, deployment did not.',
          [`CT latestCertificate.notAfter: ${ctCert.notAfter}`, `Peer cert notAfter: ${peer.notAfter}`],
          ['Redeploy the newer cert from the CT log entry to the origin.', 'Verify the CD pipeline that installs renewed certs is running.'],
          [`openssl s_client -connect ${input.domain}:443 -servername ${input.domain} </dev/null | openssl x509 -noout -dates`],
          'livetls',
        ),
      ];
    }
    // Informational: peer notAfter differs from CT latest notAfter (both valid).
    // Don't escalate — newer CT cert not yet deployed is normal.
    if (ctCert.notAfter !== peer.notAfter && !peer.expired && ctCert.daysUntilExpiry > 0) {
      return [
        f(
          'livetls.ct-peer-notafter-differs',
          'info',
          'Most recent CT cert differs from peer cert',
          'CT logs show a more recent issuance than what the origin is currently serving. Usually normal right after renewal — issuance is instant but deployment lags. Worth watching if the gap persists.',
          [`CT latest notAfter: ${ctCert.notAfter}`, `Peer notAfter: ${peer.notAfter}`, `Peer source: ${lt.source ?? 'unknown'}`],
          ['Monitor; if the peer does not catch up within your usual deploy window, investigate.'],
          [],
          'livetls',
        ),
      ];
    }
    return [];
  },
];

// RDAP rules ------------------------------------------------------------------
const rdapRules: Rule[] = [
  ({ modules, input }) => {
    const r = modules.rdap;
    if (!r?.ok || r.skipped || !input.domain) return [];
    const d = r.daysUntilExpiry;
    if (d == null) return [];
    if (d < 0) {
      return [
        f(
          'rdap.domain-expired',
          'high',
          `Domain has expired (${-d} day(s) ago)`,
          'The registration expiration date is in the past. Until the registrar or registry reaches the redemption / pending-delete phase, the domain may still resolve; after that it becomes un-renewable and a hostile re-registration becomes possible.',
          [
            `expiresAt: ${r.expiresAt ?? 'unknown'}`,
            r.registrar ? `registrar: ${r.registrar}` : '',
          ].filter(Boolean),
          ['Renew immediately via your registrar.', 'Enable auto-renew and lock the domain.'],
          [`whois ${input.domain}`],
          'rdap',
        ),
      ];
    }
    if (d < 14) {
      return [
        f(
          'rdap.domain-expiring-soon',
          'high',
          `Domain expires in ${d} day(s)`,
          'Registration expiration is imminent. If it lapses, the domain will stop resolving once the registrar flips it into hold/redemption.',
          [`expiresAt: ${r.expiresAt}`, r.registrar ? `registrar: ${r.registrar}` : ''].filter(Boolean),
          ['Renew now.', 'Enable auto-renew.', 'Enable registrar lock.'],
          [`whois ${input.domain}`],
          'rdap',
        ),
      ];
    }
    if (d < 60) {
      return [
        f(
          'rdap.domain-expiring',
          'medium',
          `Domain expires in ${d} day(s)`,
          'Expiration is within the risk window. Renewals can get stuck on payment/auth failures — renew early to leave a buffer.',
          [`expiresAt: ${r.expiresAt}`, r.registrar ? `registrar: ${r.registrar}` : ''].filter(Boolean),
          ['Renew or verify auto-renew is active.'],
          [`whois ${input.domain}`],
          'rdap',
        ),
      ];
    }
    return [];
  },
  ({ modules }) => {
    const r = modules.rdap;
    if (!r?.ok || r.skipped) return [];
    const statuses = (r.status ?? []).map((s) => s.toLowerCase());
    const locked = statuses.some((s) => s.includes('client transfer prohibited')) ||
      statuses.some((s) => s.includes('client update prohibited'));
    if (!locked && r.domain && statuses.length > 0) {
      return [
        f(
          'rdap.registrar-lock-missing',
          'medium',
          'Registrar lock does not appear to be set',
          'Without a registrar lock (clientTransferProhibited / clientUpdateProhibited), an attacker who compromises the registrar account can transfer the domain or change nameservers with minimal friction.',
          [`status: ${r.status?.join(', ') || 'none'}`],
          ['Enable registrar lock in the registrar control panel.'],
          [],
          'rdap',
        ),
      ];
    }
    return [];
  },
];

// AXFR rules ------------------------------------------------------------------
const axfrRules: Rule[] = [
  ({ modules, input }) => {
    const a = modules.axfr;
    if (!a?.ok || a.skipped || !input.domain) return [];
    const open = a.attempts.filter((at) => at.status === 'open').map((at) => at.ns);
    if (open.length === 0) return [];
    return [
      f(
        'ns.open-zone-transfer',
        'high',
        `Nameserver allows AXFR zone transfer (${open.length} server${open.length > 1 ? 's' : ''})`,
        'One or more authoritative nameservers responded to an AXFR query with a zone dump. This leaks every subdomain in the zone to anyone on the internet — attack-surface reconnaissance that is supposed to be hard becomes trivial. Restrict AXFR to known secondaries only.',
        open.map((ns) => `open on: ${ns}`),
        [
          'Restrict AXFR via `allow-transfer` (BIND) / equivalent to your secondary NS IPs only.',
          'Run `dig AXFR ' + input.domain + ' @<ns>` from outside to verify the fix.',
        ],
        open.map((ns) => `dig AXFR ${input.domain} @${ns}`),
        'axfr',
      ),
    ];
  },
];



const ALL_RULES: Rule[] = [...dnsRules, ...emailRules, ...httpRules, ...tlsRules, ...livetlsRules, ...inferenceRules, ...ipRules, ...exposureRules, ...rdapRules, ...axfrRules];

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
