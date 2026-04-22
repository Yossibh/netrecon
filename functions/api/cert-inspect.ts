import { extractCertFields, matchesHostname, type ExtractedCert } from '../../src/lib/tls-peer/cert';
import { validateHost, validateFetchUrl } from '../../src/lib/security';
import type { Finding, Severity } from '../../src/types';

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json', ...CORS_HEADERS },
  });
}

export const onRequestOptions: PagesFunction = async () =>
  new Response(null, { status: 204, headers: CORS_HEADERS });

export const onRequestPost: PagesFunction = async ({ request }) => {
  let body: { pem?: string; host?: string };
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }

  if (body.pem) {
    try {
      const certs = await parsePemBundle(body.pem);
      if (!certs.length) return json({ error: 'No PEM certificate blocks found.' }, 400);
      return json(buildReport('pem-paste', certs));
    } catch (err) {
      return json({ error: err instanceof Error ? err.message : String(err) }, 400);
    }
  }

  if (body.host) {
    const h = validateHost(body.host);
    if (!h.ok) return json({ error: h.reason }, 400);
    try {
      const certs = await fetchPeerCert(body.host);
      if (!certs.length) return json({ error: `Could not obtain a certificate for ${body.host}.` }, 400);
      return json(buildReport(`host:${body.host}`, certs, body.host));
    } catch (err) {
      return json({ error: err instanceof Error ? err.message : String(err) }, 400);
    }
  }

  return json({ error: 'Body must include "pem" or "host"' }, 400);
};

async function parsePemBundle(pem: string): Promise<ExtractedCert[]> {
  const blocks = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)];
  const certs: ExtractedCert[] = [];
  for (const b of blocks) {
    const b64 = b[1]!.replace(/\s+/g, '');
    const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    certs.push(await extractCertFields(raw));
  }
  return certs;
}

// Use the Cloudflare fetch subrequest to reach the peer. This gives us
// back the Cloudflare-terminated cert details, not the origin's raw chain,
// but it's enough for quick sanity checks (expiry, SANs, key info).
async function fetchPeerCert(host: string): Promise<ExtractedCert[]> {
  // Use inspectTls from the existing providers (CT-log backed). Prefer real
  // peer cert via the cloudflare:sockets helper if the request ever lands
  // on that path, but this endpoint keeps it simple: it uses CT logs.
  const { inspectTls } = await import('../../src/lib/providers/tls');
  const res = await inspectTls(host);
  if (res.ok && res.latestCertificate) {
    // We can't turn a CT-log record back into DER; return a synthetic
    // ExtractedCert so callers still see the most relevant fields.
    const c = res.latestCertificate;
    const now = Date.now();
    const naMs = new Date(c.notAfter).getTime();
    return [{
      subject: c.commonName || '(from CT logs)',
      issuer: c.issuer,
      notBefore: c.notBefore,
      notAfter: c.notAfter,
      sans: c.sans || [],
      signatureAlgorithm: '(not available from CT logs)',
      publicKeyAlgorithm: '(not available from CT logs)',
      serialNumber: '(not available from CT logs)',
      fingerprintSha256: '(not available from CT logs)',
      selfSigned: false,
      expired: c.daysUntilExpiry < 0,
      daysUntilExpiry: c.daysUntilExpiry,
    }];
  }
  return [];
}

function f(id: string, severity: Severity, title: string, explanation: string, evidence: string[] = [], nextSteps: string[] = []): Finding {
  return { id, severity, title, explanation, evidence, nextSteps, suggestedCommands: [], module: 'cert' };
}

function buildReport(source: string, certs: ExtractedCert[], host?: string) {
  const findings: Finding[] = [];
  const leaf = certs[0];

  for (const [i, c] of certs.entries()) {
    const role = i === 0 ? 'leaf' : i === certs.length - 1 ? 'root' : `intermediate[${i}]`;

    if (c.daysUntilExpiry < 0) {
      findings.push(f(`cert.expired.${i}`, 'high', `${role} certificate is expired`, `notAfter ${c.notAfter} is in the past. Clients will refuse the connection.`, [`${role}: ${c.subject}`], ['Renew the certificate and redeploy the full chain.']));
    } else if (c.daysUntilExpiry < 14) {
      findings.push(f(`cert.expiring-soon.${i}`, 'high', `${role} certificate expires in ${c.daysUntilExpiry} day(s)`, 'Renew now. Every downstream that pins or validates will break on expiry.', [`notAfter: ${c.notAfter}`], ['Enable automated renewal (ACME / Lets Encrypt).']));
    } else if (c.daysUntilExpiry < 30) {
      findings.push(f(`cert.expiring-30.${i}`, 'medium', `${role} certificate expires in ${c.daysUntilExpiry} day(s)`, 'Still within the usual renewal window, but worth confirming automation is healthy.', [`notAfter: ${c.notAfter}`], []));
    }

    const sigAlg = c.signatureAlgorithm.toLowerCase();
    if (sigAlg.includes('sha1') || sigAlg.includes('md5')) {
      findings.push(f(`cert.weak-sig.${i}`, 'high', `${role} uses a weak signature algorithm (${c.signatureAlgorithm})`, 'SHA-1 and MD5 are broken; modern browsers reject these in leaf certs. Reissue with SHA-256 or better.', [c.signatureAlgorithm], ['Reissue with an ECDSA-P256 or RSA-SHA256 signing profile.']));
    }

    if (c.publicKeyAlgorithm.toLowerCase().includes('rsa')) {
      // Best-effort: asn1 doesn't hand us bit length directly through our extractor. Skipping hard check.
    }

    if (i === 0 && c.selfSigned) {
      findings.push(f('cert.leaf-self-signed', 'high', 'Leaf certificate is self-signed', 'No public CA will accept this as trusted. Browsers and most clients will refuse the connection unless the cert is explicitly pinned.', [`subject == issuer == ${c.subject}`], ['Issue a certificate from a public CA (Let\'s Encrypt, ZeroSSL).']));
    }

    if (host && i === 0 && !matchesHostname(c, host)) {
      findings.push(f('cert.hostname-mismatch', 'high', `Leaf certificate does not cover ${host}`, 'The requested hostname is not in the Subject CN or any SAN. TLS clients will refuse the connection with ERR_CERT_COMMON_NAME_INVALID.', [`SANs: ${c.sans.join(', ') || '(none)'}`], [`Reissue the certificate to include ${host} in SAN.`]));
    }
  }

  const riskLevel: 'low' | 'medium' | 'high' = findings.some((x) => x.severity === 'high') ? 'high' : findings.some((x) => x.severity === 'medium') ? 'medium' : 'low';
  return {
    source,
    host: host || null,
    certs,
    findings,
    summary: {
      title: leaf ? `${leaf.subject} · ${certs.length} cert(s)` : `${certs.length} cert(s)`,
      riskLevel,
    },
    meta: { generatedAt: new Date().toISOString(), version: '1.0.0' },
  };
}
