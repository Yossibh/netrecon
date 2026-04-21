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

    // Capture the securityDetails from the main-frame navigation response.
    // Puppeteer's response.securityDetails() gives us the high-level fields
    // (protocol, cipher, issuer, subjectName, SANs, validFrom/validTo) that
    // Chrome displays in the page info panel.
    let secDetails: {
      protocol?: string; subjectName?: string; issuer?: string;
      validFrom?: number; validTo?: number; sanList?: string[];
    } | undefined;
    page.on('response', (res) => {
      if (res.url() === origin + '/' || res.url() === origin || res.url().startsWith(origin)) {
        const sd = res.securityDetails();
        if (sd && !secDetails) {
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
    });

    // 12s ceiling covers: DNS + TCP + TLS + first byte + settle. We only need
    // the TLS handshake to complete; we don't care about the DOM.
    const resp = await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 12_000 }).catch((err: unknown) => {
      // Some servers return non-HTML / non-200; we only care about the TLS.
      notes.push(`Navigation note: ${(err as Error)?.message ?? String(err)}`);
      return null;
    });

    if (resp && !secDetails) {
      // Fallback: pull from the resolved response directly.
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

    // Pull the raw DER chain. `Network.getCertificate` returns `tableNames`
    // which is actually an array of base64-encoded DER certs (CDP's field
    // naming is misleading). We pass each blob through the same pkijs
    // extractor the raw-TCP probe uses, so the output shape is identical.
    let derChain: Uint8Array[] = [];
    try {
      const rawOriginNoSlash = origin.replace(/\/+$/, '');
      const certRes = await client.send('Network.getCertificate', { origin: rawOriginNoSlash }) as { tableNames?: string[] };
      if (certRes?.tableNames?.length) {
        derChain = certRes.tableNames.map((s) => base64ToBytes(s));
      }
    } catch (err) {
      notes.push(`Could not retrieve DER chain from CDP: ${(err as Error)?.message ?? String(err)}`);
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
