// AXFR zone-transfer probe.
//
// AXFR is a DNS query type (QTYPE=252) requesting a full zone dump from an
// authoritative nameserver. Properly-configured nameservers REFUSE it from
// arbitrary clients; servers that don't are leaking their entire zone.
//
// We connect TCP/53 via Cloudflare's `connect()` API, send one AXFR request,
// read the first response message, and look at the RCODE + answer count.
// We deliberately do NOT fully replay the zone transfer - the signal is
// "did you even start sending records?" which is enough to emit a finding.
//
// This module is best-effort: connection failures, timeouts, alerts, or
// non-DNS responses all map to "skipped" or "error" on a per-NS basis and
// produce no finding. False negatives are fine; we only want true positives.

import { connect } from 'cloudflare:sockets';
import type { AxfrAttempt, AxfrModuleResult } from '@/types';

const DEFAULT_PORT = 53;
const DEFAULT_PER_NS_TIMEOUT_MS = 3_000;
const DEFAULT_MAX_NS = 2;
const QTYPE_AXFR = 252;
const QCLASS_IN = 1;

export async function probeAxfr(
  domain: string,
  nameservers: string[],
  opts: { perNsTimeoutMs?: number; maxNs?: number } = {}
): Promise<AxfrModuleResult> {
  const perNsTimeout = opts.perNsTimeoutMs ?? DEFAULT_PER_NS_TIMEOUT_MS;
  const maxNs = opts.maxNs ?? DEFAULT_MAX_NS;

  if (!nameservers.length) {
    return { ok: true, skipped: true, skipReason: 'No NS records available', domain, attempts: [] };
  }

  const picked = nameservers.slice(0, maxNs);
  const attempts: AxfrAttempt[] = [];
  let anyOpen = false;

  for (const ns of picked) {
    const r = await probeOne(domain, ns, perNsTimeout);
    attempts.push(r);
    if (r.status === 'open') anyOpen = true;
  }

  return { ok: true, domain, attempts, openTransfer: anyOpen };
}

async function probeOne(domain: string, ns: string, timeoutMs: number): Promise<AxfrAttempt> {
  // ns comes from DNS resolution; Workers connect() also refuses dangerous targets.
  // Basic sanity only: must be a valid hostname.
  if (!/^[a-z0-9.-]+$/i.test(ns) || ns.length > 253) {
    return { ns, status: 'error', error: 'invalid nameserver hostname' };
  }

  const started = Date.now();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let socket: any;
  try {
    socket = connect({ hostname: ns, port: DEFAULT_PORT }, { secureTransport: 'off', allowHalfOpen: false });
  } catch (err) {
    return { ns, status: 'error', error: `connect failed: ${(err as Error)?.message ?? String(err)}` };
  }

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let writerReleased = false;
  let readerReleased = false;
  const cleanup = async () => {
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
    const query = buildAxfrQuery(domain);
    await withTimeout(writer.write(query), timeoutMs, 'write');
    try { writer.releaseLock(); writerReleased = true; } catch { /* noop */ }

    const header = await withTimeout(readDnsHeader(reader), timeoutMs, 'read');
    if (!header) {
      return { ns, status: 'error', error: 'no response or peer closed before header', elapsedMs: Date.now() - started };
    }
    return classify(ns, header, Date.now() - started);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ns, status: /timeout/i.test(msg) ? 'timeout' : 'error', error: msg, elapsedMs: Date.now() - started };
  } finally {
    await cleanup();
  }
}

export function buildAxfrQuery(domain: string): Uint8Array {
  const msg = buildDnsMessage(domain, QTYPE_AXFR, QCLASS_IN);
  const framed = new Uint8Array(2 + msg.length);
  framed[0] = (msg.length >> 8) & 0xff;
  framed[1] = msg.length & 0xff;
  framed.set(msg, 2);
  return framed;
}

export function buildDnsMessage(domain: string, qtype: number, qclass: number): Uint8Array {
  const qname = encodeLabels(domain);
  const header = new Uint8Array(12);
  // random 16-bit id — not cryptographically important here
  const id = Math.floor(Math.random() * 0xffff);
  header[0] = (id >> 8) & 0xff;
  header[1] = id & 0xff;
  // flags: standard query, not recursive (RD=0); opcode 0; QR=0 → 0x0000
  header[2] = 0x00;
  header[3] = 0x00;
  // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
  header[4] = 0x00; header[5] = 0x01;
  header[6] = 0x00; header[7] = 0x00;
  header[8] = 0x00; header[9] = 0x00;
  header[10] = 0x00; header[11] = 0x00;

  const tail = new Uint8Array(qname.length + 4);
  tail.set(qname, 0);
  tail[qname.length] = (qtype >> 8) & 0xff;
  tail[qname.length + 1] = qtype & 0xff;
  tail[qname.length + 2] = (qclass >> 8) & 0xff;
  tail[qname.length + 3] = qclass & 0xff;

  const msg = new Uint8Array(header.length + tail.length);
  msg.set(header, 0);
  msg.set(tail, header.length);
  return msg;
}

export function encodeLabels(domain: string): Uint8Array {
  const labels = domain.replace(/\.$/, '').split('.').filter(Boolean);
  let total = 1; // trailing 0x00
  for (const l of labels) {
    if (l.length === 0 || l.length > 63) throw new Error(`invalid DNS label: ${l}`);
    total += 1 + l.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  const enc = new TextEncoder();
  for (const l of labels) {
    out[off++] = l.length;
    out.set(enc.encode(l), off);
    off += l.length;
  }
  out[off] = 0;
  return out;
}

export interface DnsResponseHeader {
  id: number;
  rcode: number;
  qr: boolean;
  aa: boolean;
  tc: boolean;
  qdcount: number;
  ancount: number;
  nscount: number;
  arcount: number;
  raw: Uint8Array;
}

export function parseDnsHeader(bytes: Uint8Array): DnsResponseHeader | null {
  if (bytes.length < 12) return null;
  const flags1 = bytes[2]!;
  const flags2 = bytes[3]!;
  return {
    id: (bytes[0]! << 8) | bytes[1]!,
    qr: (flags1 & 0x80) !== 0,
    aa: (flags1 & 0x04) !== 0,
    tc: (flags1 & 0x02) !== 0,
    rcode: flags2 & 0x0f,
    qdcount: (bytes[4]! << 8) | bytes[5]!,
    ancount: (bytes[6]! << 8) | bytes[7]!,
    nscount: (bytes[8]! << 8) | bytes[9]!,
    arcount: (bytes[10]! << 8) | bytes[11]!,
    raw: bytes,
  };
}

export function classify(ns: string, header: DnsResponseHeader, elapsedMs: number): AxfrAttempt {
  const rcodeName = rcodeName_(header.rcode);
  // Success rcodes that indicate an open transfer: NOERROR(0) with ancount > 0.
  if (header.rcode === 0 && header.ancount > 0) {
    return {
      ns,
      status: 'open',
      rcode: header.rcode,
      rcodeName,
      ancount: header.ancount,
      elapsedMs,
    };
  }
  // REFUSED(5) or NOTAUTH(9) are the "good" expected responses.
  if (header.rcode === 5 || header.rcode === 9 || header.rcode === 4) {
    return {
      ns,
      status: 'refused',
      rcode: header.rcode,
      rcodeName,
      ancount: header.ancount,
      elapsedMs,
    };
  }
  // Anything else: ambiguous — treat as "responded" without raising a finding.
  return {
    ns,
    status: 'other',
    rcode: header.rcode,
    rcodeName,
    ancount: header.ancount,
    elapsedMs,
  };
}

function rcodeName_(rcode: number): string {
  const map: Record<number, string> = {
    0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP',
    5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE',
  };
  return map[rcode] ?? `RCODE${rcode}`;
}

async function withTimeout<T>(p: Promise<T>, ms: number, tag: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${tag} timeout after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }).catch((e) => { clearTimeout(timer); reject(e); });
  });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function readDnsHeader(reader: any): Promise<DnsResponseHeader | null> {
  // Over TCP, DNS messages are prefixed with a 2-byte big-endian length.
  const prefix = await readExactly(reader, 2);
  if (!prefix) return null;
  const len = (prefix[0]! << 8) | prefix[1]!;
  if (len < 12) return null;
  // We only need the first 12 bytes (the DNS header) to classify.
  const want = Math.min(len, 12);
  const body = await readExactly(reader, want);
  if (!body) return null;
  return parseDnsHeader(body);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function readExactly(reader: any, n: number): Promise<Uint8Array | null> {
  const parts: Uint8Array[] = [];
  let got = 0;
  while (got < n) {
    const { value, done } = await reader.read();
    if (done) return null;
    if (!(value instanceof Uint8Array)) return null;
    parts.push(value);
    got += value.length;
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    const take = Math.min(p.length, n - off);
    out.set(p.subarray(0, take), off);
    off += take;
    if (off >= n) break;
  }
  return out;
}
