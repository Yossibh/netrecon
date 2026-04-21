// Peer TLS inspection via Cloudflare Browser Rendering.
//
// Used as a fallback for targets that our raw-TCP fast path can't reach:
//   - Cloudflare-fronted hosts (CF blocks Worker connect() to its own IPs)
//   - TLS 1.3-only servers (Certificate is encrypted under handshake secrets)
//
// How it works: spin up a headless Chromium via the `@cloudflare/puppeteer`
// binding, navigate to https://host/, attach a Chrome DevTools Protocol
// session, and ask Chrome for the peer cert chain via `Network.getCertificate`.
// That command returns the chain as base64-encoded DER blobs, which we then
// pass through the same pkijs extraction path the raw-TCP probe uses.
//
// Cost model: on the Workers Free plan, Browser Rendering gives 10 browser-
// minutes per day and 3 concurrent sessions. A typical cert check here is
// ~3-5s, so ~120-200 checks/day. Plenty for portfolio traffic. If we blow
// past the limit, CF returns an error that we surface cleanly.

import puppeteer, { type Browser } from '@cloudflare/puppeteer';
import { validateHost } from '../security';
import { extractCertFields, matchesHostname, type ExtractedCert } from './cert';
import { tlsVersionName } from './records';

export interface BrowserProbeResult {
  ok: boolean;
  host: string;
  port: number;
  source: 'browser-rendering';
  negotiatedVersion?: string;
  cipherSuite?: string;
  certs?: ExtractedCert[];
  hostnameMatch?: boolean;
  alpn?: string;
  error?: string;
  durationMs: number;
  notes: string[];
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Chrome ships CDP protocol names like "TLS 1.3", "TLS 1.2" already in the
// exact human-readable form we use elsewhere, so no translation needed.
function normalizeProto(p?: string): string | undefined {
  if (!p) return undefined;
  return p;
}

export async function inspectPeerTlsBrowser(
  browserBinding: unknown,
  host: string,
  port = 443,
): Promise<BrowserProbeResult> {
  const started = Date.now();
  const notes: string[] = [];
  const result: BrowserProbeResult = {
    ok: false, host, port, source: 'browser-rendering', durationMs: 0, notes,
  };

  const v = validateHost(host);
  if (!v.ok) { result.error = v.reason; result.durationMs = Date.now() - started; return result; }

  if (!browserBinding) {
    result.error = 'Browser Rendering binding is not available in this environment.';
    result.durationMs = Date.now() - started;
    return result;
  }

  let browser: Browser | undefined;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    browser = await puppeteer.launch(browserBinding as any);
    const page = await browser.newPage();
    const client = await page.target().createCDPSession();
    await client.send('Network.enable');
    await client.send('Security.enable');

    const origin = port === 443 ? `https://${host}` : `https://${host}:${port}`;

    // Listen for Security.visibleSecurityStateChanged BEFORE navigating.
    // This event carries certificateSecurityState.certificate which is an
    // array of base64 DER blobs — the full peer chain. It's more reliable
    // than Network.getCertificate for CF-fronted targets where the latter
    // returns an empty chain.
    let securityStateDer: Uint8Array[] = [];
    let securityStateInfo: {
      protocol?: string; cipher?: string; keyExchange?: string;
      subjectName?: string; issuer?: string; validFrom?: number; validTo?: number;
    } | undefined;
    let securityStateReceived = false;
    const securityStatePromise = new Promise<void>((resolve) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      client.on('Security.visibleSecurityStateChanged', (evt: any) => {
        try {
          const vss = evt?.visibleSecurityState ?? {};
          const cs = vss.certificateSecurityState;
          if (!cs) return;
          if (Array.isArray(cs.certificate) && cs.certificate.length) {
            securityStateDer = cs.certificate.map((s: string) => base64ToBytes(s));
          }
          securityStateInfo = {
            protocol: cs.protocol,
            cipher: cs.cipher,
            keyExchange: cs.keyExchange,
            subjectName: cs.subjectName,
            issuer: cs.issuer,
            validFrom: cs.validFrom,
            validTo: cs.validTo,
          };
          securityStateReceived = true;
          resolve();
        } catch { /* ignore malformed events */ }
      });
    });

    // 12s ceiling covers: DNS + TCP + TLS + first byte + settle. We only need
    // the TLS handshake to complete; we don't care about the DOM.
    const resp = await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 12_000 }).catch((err: unknown) => {
      // Some servers return non-HTML / non-200; we only care about the TLS.
      notes.push(`Navigation note: ${(err as Error)?.message ?? String(err)}`);
      return null;
    });

    // Give Security.visibleSecurityStateChanged up to 2s to arrive. It usually
    // fires during navigation but sometimes lands just after domcontentloaded.
    if (!securityStateReceived) {
      await Promise.race([
        securityStatePromise,
        new Promise((r) => setTimeout(r, 2000)),
      ]);
    }

    // Pull high-level security details from the final navigation response.
    // Using resp directly (not a response listener) makes sure we're looking
    // at the post-redirect response, not an intermediate 301 whose
    // securityDetails may be sparse.
    let secDetails: {
      protocol?: string; subjectName?: string; issuer?: string;
      validFrom?: number; validTo?: number; sanList?: string[];
    } | undefined;
    if (resp) {
      const sd = resp.securityDetails();
      if (sd) {
        secDetails = {
          protocol: sd.protocol(),
          subjectName: sd.subjectName(),
          issuer: sd.issuer(),
          validFrom: sd.validFrom(),
          validTo: sd.validTo(),
          sanList: (sd as unknown as { subjectAlternativeNames?: () => string[] }).subjectAlternativeNames?.() ?? [],
        };
      }
    }

    // Preferred DER source: Security.visibleSecurityStateChanged event.
    let derChain: Uint8Array[] = securityStateDer;

    // Secondary DER source: Network.getCertificate({origin}). Try final
    // redirected origin first, then the requested one.
    if (derChain.length === 0) {
      const originsToTry: string[] = [];
      try {
        if (resp) {
          const finalOrigin = new URL(resp.url()).origin;
          if (finalOrigin) originsToTry.push(finalOrigin);
        }
      } catch { /* ignore URL parse errors */ }
      const requestedOrigin = origin.replace(/\/+$/, '');
      if (!originsToTry.includes(requestedOrigin)) originsToTry.push(requestedOrigin);
      for (const o of originsToTry) {
        try {
          // eslint-disable-next-line no-await-in-loop
          const certRes = await client.send('Network.getCertificate', { origin: o }) as { tableNames?: string[] };
          if (certRes?.tableNames?.length) {
            derChain = certRes.tableNames.map((s) => base64ToBytes(s));
            break;
          }
        } catch { /* try next */ }
      }
    }

    // Merge: prefer structured securityStateInfo (issuer, subjectName, etc.)
    // from the CDP Security event over Puppeteer's SecurityDetails, since the
    // former is populated more reliably on CF edge.
    if (securityStateInfo) {
      secDetails = {
        protocol: securityStateInfo.protocol ?? secDetails?.protocol,
        subjectName: securityStateInfo.subjectName ?? secDetails?.subjectName,
        issuer: securityStateInfo.issuer || secDetails?.issuer,
        validFrom: securityStateInfo.validFrom ?? secDetails?.validFrom,
        validTo: securityStateInfo.validTo ?? secDetails?.validTo,
        sanList: secDetails?.sanList ?? [],
      };
    }

    if (derChain.length === 0) {
      notes.push('Raw DER chain not retrievable via CDP for this target. Using Chrome-parsed fields only; fingerprint/serial/sigAlg will be empty.');
    }

    const extracted: ExtractedCert[] = [];
    for (const der of derChain) {
      try {
        // eslint-disable-next-line no-await-in-loop
        extracted.push(await extractCertFields(der));
      } catch (err) {
        notes.push(`Cert parse error: ${(err as Error)?.message ?? String(err)}`);
      }
    }

    // Patch-up pass: if pkijs extraction succeeded but left issuer/subject
    // empty (observed on some Cloudflare-edge certs where pkijs parses DER,
    // extracts fingerprint/serial/sigAlg/notBefore/notAfter fine, but
    // RelativeDistinguishedNames.typesAndValues comes back empty for the
    // issuer RDN), fall back to the human-readable strings Chrome already
    // parsed and exposed via CDP Security.visibleSecurityStateChanged /
    // Puppeteer SecurityDetails. This guarantees users always see *some*
    // issuer/subject value on the browser path, which is critical for TLS
    // troubleshooting (issuer identifies the CA that signed the leaf).
    if (extracted.length > 0 && secDetails) {
      const leaf = extracted[0]!;
      if (!leaf.issuer && secDetails.issuer) {
        leaf.issuer = secDetails.issuer;
        notes.push('Leaf issuer extracted via CDP security state (pkijs RDN decode returned empty for this cert).');
      }
      if (!leaf.subject && secDetails.subjectName) {
        leaf.subject = secDetails.subjectName;
      }
      if ((!leaf.sans || leaf.sans.length === 0) && secDetails.sanList?.length) {
        leaf.sans = secDetails.sanList;
      }
      if (!leaf.issuer) {
        notes.push('Issuer could not be parsed from the certificate returned by Browser Rendering and was not exposed by Chrome. This is a known limitation for some Cloudflare-fronted targets; use the fast path (raw TCP) for authoritative issuer data on non-CF hosts.');
      }
    }

    if (extracted.length === 0 && secDetails) {
      // No raw DER (Chrome sometimes doesn't surface it for cached/aborted
      // nav); fall back to the high-level fields Chrome already parsed.
      notes.push('Raw DER unavailable from CDP; returning Chrome-parsed security details without fingerprint/serial.');
      const notBefore = secDetails.validFrom ? new Date(secDetails.validFrom * 1000).toISOString() : '';
      const notAfter  = secDetails.validTo  ? new Date(secDetails.validTo  * 1000).toISOString() : '';
      const now = Date.now();
      const naMs = secDetails.validTo ? secDetails.validTo * 1000 : 0;
      extracted.push({
        subject: secDetails.subjectName ?? '',
        issuer: secDetails.issuer ?? '',
        notBefore,
        notAfter,
        sans: secDetails.sanList ?? [],
        signatureAlgorithm: 'unknown',
        publicKeyAlgorithm: 'unknown',
        serialNumber: '',
        fingerprintSha256: '',
        selfSigned: false,
        expired: naMs > 0 && now > naMs,
        daysUntilExpiry: naMs > 0 ? Math.floor((naMs - now) / 86400000) : 0,
      });
    }

    if (extracted.length === 0) {
      result.error = 'Could not extract any certificate data from the browser probe.';
      return result;
    }

    result.certs = extracted;
    result.hostnameMatch = matchesHostname(extracted[0]!, host);
    result.negotiatedVersion = normalizeProto(secDetails?.protocol);
    result.alpn = resp ? (resp.request().headers()[':protocol'] as string | undefined) : undefined;
    result.ok = true;

    if (extracted[0]!.expired) notes.push('Leaf certificate is expired as of this check.');
    if (extracted[0]!.daysUntilExpiry >= 0 && extracted[0]!.daysUntilExpiry < 14) {
      notes.push(`Leaf certificate expires in ${extracted[0]!.daysUntilExpiry} day(s).`);
    }
    if (!result.hostnameMatch) notes.push('Leaf certificate SANs do not match the requested hostname.');

    return result;
  } catch (err) {
    const msg = (err as Error)?.message ?? String(err);
    // Browser Rendering rate-limit / quota errors are friendly to surface.
    if (/quota|limit|exceed/i.test(msg)) {
      result.error = `Browser Rendering quota exceeded: ${msg}`;
      notes.push('Free plan allows 10 browser-minutes/day and 3 concurrent sessions.');
    } else {
      result.error = msg;
    }
    return result;
  } finally {
    try { if (browser) await browser.close(); } catch { /* swallow */ }
    result.durationMs = Date.now() - started;
  }
}

// Reference to silence unused-import warning if the file is imported but not
// called in a given build. (tlsVersionName is used to align protocol strings
// in future enhancements, e.g. mapping Chrome's "QUIC" or "HTTP/3" markers.)
void tlsVersionName;
