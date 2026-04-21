// Live peer TLS inspection — hybrid: raw-TCP fast path + browser fallback.
//
// Fast path (this file): open a raw TCP socket via Cloudflare's `connect()`
// API, hand-craft a TLS 1.2 ClientHello with SNI, read the plaintext server
// flight (ServerHello + Certificate), extract cert fields with pkijs. Fast
// (<500ms), free, but has two blind spots:
//   1. Cloudflare blocks outbound from Workers to its own IP ranges, so any
//      CF-fronted target returns "Stream was cancelled." (~20% of the web.)
//   2. TLS 1.3-only servers send an encrypted Certificate message we can't
//      read without a full handshake implementation.
//
// Fallback path (browser.ts): a headless Chromium via the Browser Rendering
// binding, which sidesteps both blind spots (it's a real browser, not a
// Worker, so CF routes its traffic normally; and Chrome speaks full TLS 1.3).
// Slower (~3-5s) and capped at 10 browser-minutes/day on the Free plan, so
// we only use it when the fast path fails in one of the two known ways.

import { connect } from 'cloudflare:sockets';
import { validateHost } from '../security';
import { buildClientHello } from './client-hello';
import {
  readServerFlight,
  parseServerHello,
  parseCertificateMessage,
  alertName,
  cipherSuiteName,
  tlsVersionName,
} from './records';
import { extractCertFields, matchesHostname, type ExtractedCert } from './cert';
import { inspectPeerTlsBrowser } from './browser';

export interface PeerTlsResult {
  ok: boolean;
  host: string;
  port: number;
  source: 'raw-tcp' | 'browser-rendering';
  negotiatedVersion?: string;
  cipherSuite?: string;
  certs?: ExtractedCert[];
  hostnameMatch?: boolean;
  error?: string;
  alert?: { level: number; description: string };
  durationMs: number;
  bytesRead?: number;
  notes: string[];
  fellBackTo?: 'browser-rendering';
  fastPathError?: string;
}

const HANDSHAKE_TIMEOUT_MS = 5000;

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`timeout after ${ms}ms: ${label}`)), ms)),
  ]);
}

/** Should we ask the browser to retry this target after the fast path? */
function shouldFallbackToBrowser(r: PeerTlsResult): boolean {
  if (r.ok) return false;
  if (r.alert?.description === 'protocol_version') return true;          // TLS 1.3-only
  if (r.error?.includes('Stream was cancelled')) return true;            // CF-blocked
  if (r.error?.includes('Peer negotiated TLS 1.3')) return true;
  return false;
}

async function fastPath(host: string, port: number): Promise<PeerTlsResult> {
  const started = Date.now();
  const notes: string[] = [];
  const result: PeerTlsResult = { ok: false, host, port, source: 'raw-tcp', durationMs: 0, notes };

  const v = validateHost(host);
  if (!v.ok) { result.error = v.reason; result.durationMs = Date.now() - started; return result; }

  const looksLikeIp = /^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-fA-F:]+\]?)$/.test(host);
  if (looksLikeIp) {
    result.error = 'Live peer TLS requires a hostname (SNI). IP-only inputs cannot set SNI.';
    result.durationMs = Date.now() - started;
    return result;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let socket: any;
  try {
    socket = connect({ hostname: host, port }, { secureTransport: 'off', allowHalfOpen: false });
  } catch (err) {
    result.error = `Connect failed: ${(err as Error)?.message ?? String(err)}`;
    result.durationMs = Date.now() - started;
    return result;
  }

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let writerReleased = false;
  let readerReleased = false;
  const releaseAndClose = async () => {
    try { if (!writerReleased) { writer.releaseLock(); writerReleased = true; } } catch { /* noop */ }
    try {
      if (!readerReleased) {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
        readerReleased = true;
      }
    } catch { /* noop */ }
    try { await socket.close().catch(() => {}); } catch { /* noop */ }
  };

  try {
    const hello = buildClientHello(host);
    await withTimeout(writer.write(hello), HANDSHAKE_TIMEOUT_MS, 'write ClientHello');
    try { writer.releaseLock(); writerReleased = true; } catch { /* noop */ }

    const flight = await withTimeout(readServerFlight(reader), HANDSHAKE_TIMEOUT_MS, 'read handshake');
    result.bytesRead = flight.bytesRead;

    if (flight.alert) {
      const name = alertName(flight.alert.description);
      result.alert = { level: flight.alert.level, description: name };
      if (name === 'protocol_version') {
        result.error = 'Peer rejected TLS 1.2 with protocol_version alert. Likely TLS 1.3-only.';
        notes.push('Fast path cannot inspect TLS 1.3-encrypted Certificates; browser fallback will take over.');
      } else if (name === 'handshake_failure' || name === 'insufficient_security') {
        result.error = `Peer rejected our ClientHello with ${name}. Likely no shared cipher suite or sig algorithm.`;
      } else if (name === 'unrecognized_name') {
        result.error = `Peer does not have a certificate for SNI "${host}" (alert: ${name}).`;
      } else {
        result.error = `Peer sent fatal alert: ${name}`;
      }
      return result;
    }

    if (!flight.serverHello) {
      result.error = flight.endedEarly
        ? 'Peer closed connection before sending ServerHello.'
        : 'Did not receive ServerHello within handshake budget.';
      return result;
    }

    const sh = parseServerHello(flight.serverHello.body);
    if (!sh) { result.error = 'Malformed ServerHello.'; return result; }
    result.negotiatedVersion = tlsVersionName(sh.negotiatedVersion);
    result.cipherSuite = cipherSuiteName(sh.cipherSuite);

    if (sh.negotiatedVersion === 0x0304) {
      result.error = 'Peer negotiated TLS 1.3 despite our 1.2-only hello; Certificate is encrypted.';
      notes.push('Fast path cannot decrypt 1.3 Certificate; browser fallback will take over.');
      return result;
    }

    if (!flight.certificate) {
      result.error = flight.endedEarly
        ? 'Peer closed connection before sending Certificate.'
        : 'No Certificate message observed before handshake budget elapsed.';
      return result;
    }

    const derChain = parseCertificateMessage(flight.certificate.body);
    if (!derChain || derChain.length === 0) { result.error = 'Empty or malformed Certificate message.'; return result; }

    const extracted: ExtractedCert[] = [];
    for (let i = 0; i < derChain.length; i++) {
      try {
        // eslint-disable-next-line no-await-in-loop
        extracted.push(await extractCertFields(derChain[i]!));
      } catch (err) {
        notes.push(`Cert #${i} parse error: ${(err as Error)?.message ?? String(err)}`);
      }
    }
    if (extracted.length === 0) { result.error = 'All peer certs failed to parse.'; return result; }
    result.certs = extracted;
    result.hostnameMatch = matchesHostname(extracted[0]!, host);
    result.ok = true;

    if (extracted[0]!.expired) notes.push('Leaf certificate is expired as of this check.');
    if (extracted[0]!.daysUntilExpiry >= 0 && extracted[0]!.daysUntilExpiry < 14) {
      notes.push(`Leaf certificate expires in ${extracted[0]!.daysUntilExpiry} day(s).`);
    }
    if (!result.hostnameMatch) notes.push('Leaf certificate SANs do not match the requested hostname.');

    return result;
  } catch (err) {
    result.error = (err as Error)?.message ?? String(err);
    return result;
  } finally {
    await releaseAndClose();
    result.durationMs = Date.now() - started;
  }
}

/**
 * Inspect the TLS cert actually served by host:port.
 *
 * @param host   ASCII hostname; IP inputs are rejected (SNI required).
 * @param port   defaults to 443.
 * @param browserBinding  optional `env.BROWSER` Browser Rendering binding;
 *                        when provided, enables the browser fallback for
 *                        CF-fronted and TLS 1.3-only targets.
 */
export async function inspectPeerTls(
  host: string,
  port = 443,
  browserBinding?: unknown,
): Promise<PeerTlsResult> {
  const fast = await fastPath(host, port);
  if (fast.ok || !browserBinding || !shouldFallbackToBrowser(fast)) return fast;

  const fallback = await inspectPeerTlsBrowser(browserBinding, host, port);
  const merged: PeerTlsResult = {
    ok: fallback.ok,
    host: fallback.host,
    port: fallback.port,
    source: 'browser-rendering',
    negotiatedVersion: fallback.negotiatedVersion,
    cipherSuite: fallback.cipherSuite,
    certs: fallback.certs,
    hostnameMatch: fallback.hostnameMatch,
    error: fallback.error,
    durationMs: fast.durationMs + fallback.durationMs,
    notes: [
      `Fast path (raw TCP) could not inspect this target (${fast.error}). Fell back to Browser Rendering.`,
      ...fallback.notes,
    ],
    fellBackTo: 'browser-rendering',
    fastPathError: fast.error,
  };
  return merged;
}

